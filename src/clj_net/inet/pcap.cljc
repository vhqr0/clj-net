(ns clj-net.inet.pcap
  (:require [clj-bytes.struct :as st]))

(def pcap-be-ms-magic 0xa1b2c3d4)
(def pcap-le-ms-magic 0xd4c3b2a1)
(def pcap-be-ns-magic 0xa1b23c4d)
(def pcap-le-ns-magic 0x4d3cb2a1)

(def pcap-magic-map
  {:be-ms pcap-be-ms-magic
   :le-ms pcap-le-ms-magic
   :be-ns pcap-be-ns-magic
   :le-ns pcap-le-ns-magic})

(def st-pcap-magic
  (st/enum st/uint32-be pcap-magic-map))

(defn st-pcap-header
  [be?]
  (let [st-uint16 (if be? st/uint16-be st/uint16-le)
        st-uint32 (if be? st/uint32-be st/uint32-le)]
    (st/keys
     :vermaj st-uint16
     :vermin st-uint16
     :tz st-uint32
     :sig st-uint32
     :snaplen st-uint32
     :linktype st-uint32)))

(def st-pcap-be-header (st-pcap-header true))
(def st-pcap-le-header (st-pcap-header false))

(defn st-pcap-packet
  [be?]
  (let [st-uint32 (if be? st/uint32-be st/uint32-le)]
    (st/keys
     :sec st-uint32
     :usec st-uint32
     :caplen st-uint32
     :wirelen st-uint32
     :data st/bytes)))

(def st-pcap-be-packet (st-pcap-packet true))
(def st-pcap-le-packet (st-pcap-packet false))
