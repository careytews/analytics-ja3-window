#!/usr/bin/env python3

#############################################################################
# 
# ja3 window analytic: Looks for unrecognised_stream events, and if there is a
# hello handshake in the payload then try to extract ja3 signature
# 
# Summary information includes: src, dest, device and ja3 md5 digest
# 
# This window analytic works on small windows with large amounts of data
# by spraying the data across multiple instances of this analytic.
# The idea is that the analytic running downstream can combine these windows
# into a single summary.
#
#############################################################################

import PyAnalyticsCommon as analytics
import sys
import datetime
import time
import pickle
import json
import threading
import re
import hashlib
import os
import queue
import uuid
import argparse
import dpkt
import socket
import struct
from hashlib import md5
import base64
import codecs

#############################################################################
# Setup AMQP etc.
#############################################################################

sys.stdout.write("Create AMQP connections...\n")
sys.stdout.flush()

broker=os.getenv("AMQP_BROKER", "amqp")

in_ex=os.getenv("AMQP_INPUT_EXCHANGE", "trust_event")
in_q=os.getenv("AMQP_INPUT_QUEUE", "worker.ja3-window.in")

out_ex=os.getenv("AMQP_OUTPUT_EXCHANGE", "default")
#out_q=os.getenv("AMQP_OUTPUT_QUEUE", "worker.ja3-window.out")
window_key=os.getenv("AMQP_WINDOW_ROUTING_KEY", "ja3-window.key")

analytics.setup('ja3-window')
con = analytics.Subscriber(broker=broker, queue=in_q, routing_key="", 
                            exchange=in_ex, exchange_type="fanout")
window_pub = analytics.Publisher(broker=broker, routing_key=window_key, 
                            exchange=out_ex)

# Time period on which to emit summaries.
window_time=2

# Am I still running?
running=True

sys.stdout.write("Configured.\n")
sys.stdout.flush()

#############################################################################
# Initialise state
#############################################################################

# 
# ja3 information state.  This is a map:
# - key: (device, ja3) tuple.
# - value: map:
#   - key: "count"
#     value: Count of ja3 invocations.
#   - key: "times"
#     value: A set of times, seconds since 1970.
#
ja3_info={}

# Time logged at start of this window period
period_start=int(time.time())

# Concurrency lock
lock=threading.Lock()


#############################################################################
# Thread, emits the window state periodically, and resets it
#############################################################################

count=0

class Outputter(threading.Thread):

    # Constructor: Call thread initialisation
    def __init__(self):
        threading.Thread.__init__(self)
        pass
    
    # Thread body
    def run(self):

        global ja3_info, period_start, window_pub, count

        while running:

            # Wait over window time
            time.sleep(window_time)

            sys.stdout.write("Seen %d messages.\n" % count)
            sys.stdout.flush()

            if len(ja3_info):

                # Stop the other thread from modifying state
                lock.acquire()

                try:

                    # Bundle the window start time in with the object.
                    output = (period_start, ja3_info)

                    while running:

                        try:
                            window_pub.publish(pickle.dumps(output))
                            break

                        except Exception as e:

                            sys.stderr.write("Exception: %s\n" % e)
                            sys.stderr.flush()

                            # Re-connect
                            window_pub.connect()
                        
                            sys.stderr.write("Publish failed, retrying...\n")
                            sys.stderr.flush()
                            time.sleep(5)

                    # Reset domain state
                    ja3_info={}
                    period_start = int(time.time())

                except Exception as e:
                    sys.stderr.write("Exception: %s\n" % e)
                    sys.stderr.flush()

                    # On exception, reset the state.  Can't meaningfully recover.
                    ja3_info={}
                    period_start = int(time.time())

                # Release lock
                lock.release()

#############################################################################
# ja3 functions to generate ja3digest from TLS handshake message
#############################################################################

def update_state(obj):
    
    # Ignore stuff which isn't unrecognised_stream.
    if obj["action"] != "unrecognised_stream": return
    ustream = obj["unrecognised_stream"]
    if 'payload' not in ustream: return
        
    # Get time in event.
    evt = datetime.datetime.strptime(obj["time"], "%Y-%m-%dT%H:%M:%S.%fZ")

    evttime = evt

    # Convert to UNIX time
    evt = time.mktime(evt.timetuple())
    
    # Going to modify state, acquire the state lock.
    lock.acquire()
    
    try:
        result = getja3(obj)
        #sys.stdout.write(str(result))
        if(len(result)>1):
            if(result[0].startswith('ja3:')):
                ja3out = result[1]                                
                # Construct an index of: device, ja3digest.
                # This is effectively used to group the data.
                ix = (obj["device"], ja3out)

                # Initialise the state for this key if it does not exist.
                if ix not in ja3_info:
                    ja3_info[ix] = {
                        "times": set(),
                        "count": 0,
                    }
                ja3 = ja3_info[ix]

                # Update ja3 type counts.

                # Increment time distribution.  An array holds a count of
                # ja3digests, one per second of time since the window
                # start.
                ja3["times"].add(evt)
                ja3["count"] += 1

    except Exception as e:
        sys.stderr.write("Exception: %s\n" % e)
        sys.stderr.flush()

    # Release the lions!  I mean lock.
    lock.release()


def ntoh(buf):
    """Convert to network order.

    :param buf: Bytes to convert
    :type buf: bytearray
    :returns: int
    """
    if len(buf) == 1:
        return buf[0]
    elif len(buf) == 2:
        return struct.unpack('!H', buf)[0]
    elif len(buf) == 4:
        return struct.unpack('!I', buf)[0]
    else:
        raise ValueError('Invalid input buffer size for NTOH')


def process_extensions(client_handshake):
    """Process any extra extensions and convert to a JA3 segment.

    :param client_handshake: Handshake data from the packet
    :type client_handshake: dpkt.ssl.TLSClientHello
    :returns: list
    """
    if not hasattr(client_handshake, "extensions"):
        # Needed to preserve commas on the join
        return ["", "", ""]

    exts = list()
    elliptic_curve = ""
    elliptic_curve_point_format = ""
    for ext_val, ext_data in client_handshake.extensions:
        if not GREASE_TABLE.get(ext_val):
            exts.append(ext_val)
        if ext_val == 0x0a:
            a, b = parse_variable_array(ext_data, 2)
            # Elliptic curve points (16 bit values)
            elliptic_curve = convert_to_ja3_segment(a, 2)
        elif ext_val == 0x0b:
            a, b = parse_variable_array(ext_data, 1)
            # Elliptic curve point formats (8 bit values)
            elliptic_curve_point_format = convert_to_ja3_segment(a, 1)
        else:
            continue

    results = list()
    results.append("-".join([str(x) for x in exts]))
    results.append(elliptic_curve)
    results.append(elliptic_curve_point_format)
    return results


def convert_to_ja3_segment(data, element_width):
    """Convert a packed array of elements to a JA3 segment.

    :param data: Current PCAP buffer item
    :type: str
    :param element_width: Byte count to process at a time
    :type element_width: int
    :returns: str
    """
    int_vals = list()
    data = bytearray(data)
    if len(data) % element_width:
        message = '{count} is not a multiple of {width}'
        message = message.format(count=len(data), width=element_width)
        raise ValueError(message)

    for i in range(0, len(data), element_width):
        element = ntoh(data[i: i + element_width])
        if element not in GREASE_TABLE:
            int_vals.append(element)

    return "-".join(str(x) for x in int_vals)



def parse_variable_array(buf, byte_len):
    """Unpack data from buffer of specific length.
    :param buf: Buffer to operate on
    :type buf: bytes
    :param byte_len: Length to process
    :type byte_len: int
    :returns: bytes, int
    """
    _SIZE_FORMATS = ['!B', '!H', '!I', '!I']
    assert byte_len <= 4
    size_format = _SIZE_FORMATS[byte_len - 1]
    padding = b'\x00' if byte_len == 3 else b''
    size = struct.unpack(size_format, padding + buf[:byte_len])[0]
    data = buf[byte_len:byte_len + size]

    return data, size + byte_len


GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}
# GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
SSL_PORT = 443
TLS_HANDSHAKE = 22

def getja3 (event):

    ustream = event["unrecognised_stream"]
    payload = ustream['payload']
    if payload == None:
       return [str('NoJA3:'),str('NoJA3:')]
    src = 'nosrc'
    dest = 'nodest'
    device = 'nodevice'

    if 'src' in event:
     srclist = event["src"]
     if len(srclist)>2:
      del(srclist[2])
      src = str(srclist).replace('\'','"')

    if 'dest' in event:
     destlist = event["dest"]
     if len(destlist)>2:
      del(destlist[2])
      dest = str(destlist).replace('\'','"')

    if 'device' in event:
     device = event["device"]    

    b64data = base64.b64decode(payload)

    tls_handshake = bytearray(b64data)
    if tls_handshake[0] != TLS_HANDSHAKE:
        return [str('NoJA3:'),str(tls_handshake[0])]
  
    records = list()
    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(b64data)
    except dpkt.ssl.SSL3Exception:
        return ['NoJA3:','dpkt.ssl.SSL3Exception']
    except dpkt.dpkt.NeedData:        
        return ['NoJA3:','dpkt.dpkt.NeedData']
    except Exception as e:
        return ['NoJA3:',e]
    #print("len(records):"+str(len(records))) 
    if len(records) <= 0:
        return ['NoJA3:','NoRecords']       
    #print("len(records):"+str(len(records))) 
    for record in records:
        if record.type != TLS_HANDSHAKE:
            continue
        if len(record.data) == 0:
            continue        
        try: 
            client_hello = bytearray(record.data)
        except client_hello:
            continue

        if client_hello[0] != 1:
            #We only want client HELLO
            continue
        try:
            handshake = dpkt.ssl.TLSHandshake(record.data)
        except dpkt.dpkt.NeedData:
            #Looking for a handshake here  
            continue
        if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
            #Still not the HELLO  
            continue
        client_handshake = handshake.data
        buf, ptr = parse_variable_array(client_handshake.data, 1)
        buf, ptr = parse_variable_array(client_handshake.data[ptr:], 2)
        ja3 = [str(client_handshake.version)]

        # Cipher Suites (16 bit values)
        ja3.append(convert_to_ja3_segment(buf, 2))
        ja3 += process_extensions(client_handshake)
        ja3 = ",".join(ja3)
        ja3digest = md5(ja3.encode()).hexdigest()
        #record = '{"src":' + src + ',"dest":' + dest +',"device":"' + device + '","ja3digest":"' + ja3digest + '"}'
        record = '{"src":' + src + ',"ja3digest":"' + ja3digest + '"}'
        return ['ja3:', record]

# Handler, called for each incoming message.
def callback(body):

    global count

    count = count + 1
    
    try:        
        # Decode JSON body to event.
        obj = json.loads(body)
        # Update ja3 state
        update_state(obj)
       
    except Exception as e:
        sys.stderr.write("Exception: %s\n" % e)
        sys.stderr.flush()


# Start up the output thread.
Outputter().start()

sys.stdout.write("Initialised, start consuming...\n")
sys.stdout.flush()

con.consume(callback)