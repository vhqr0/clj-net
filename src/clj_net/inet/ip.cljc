(ns clj-net.inet.ip
  (:require [clj-bytes.core :as b]
            [clj-bytes.struct :as st]
            [clj-net.inet.packet :as pkt]))

(defn sum
  "Get inet sum."
  [b]
  (let [s (->> (b/useq b)
               (partition-all 2)
               (reduce
                (fn [s [l r]]
                  (-> (+ s (bit-shift-left l 8) (or r 0))
                      ;; reserve last 6 bytes
                      (bit-and 0xffffffffffff)))
                0))
        s (+ (bit-shift-right s 16) (bit-and s 0xffff))
        s (+ (bit-shift-right s 16) s)]
    (bit-and s 0xffff)))

(defn checksum
  "Get inet checksum, return int."
  [b]
  (bit-and (- (inc (sum b))) 0xffff))

(def ip-proto-map
  (st/->kimap
   {:ipv6-no-next       59
    :ipv6-ext-hbh-opts   0
    :ipv6-ext-dest-opts 60
    :ipv6-ext-routing   43
    :ipv6-ext-fragment  44
    :ipv6-ext-esp       50
    :ipv6-ext-ah        51
    :icmpv4              1
    :icmpv6             58
    :tcp                 6
    :udp                17}))

(defmethod pkt/parse :ip [_type opts context buffer]
  (when-not (b/empty? buffer)
    (let [version (-> (b/uget buffer 0) (bit-shift-right 4))]
      (case version
        4 (pkt/parse :ipv4 opts context buffer)
        6 (pkt/parse :ipv6 opts context buffer)))))

(defn parse-ip-xform
  [{:ip/keys [proto-map]} packet context version id proto src dst plen]
  (let [proto (when (some? proto) (get-in proto-map [:i->k proto]))
        context (merge context #:ip{:version version :id id :proto proto :src src :dst dst :plen plen})]
    [packet context {:next-type proto :next-length plen}]))

(defn parse-ip-ext-xform
  [{:ip/keys [proto-map]} packet context proto]
  (let [proto (when (some? proto) (get-in proto-map [:i->k proto]))
        context (merge context #:ip{:proto proto})]
    [packet context {:next-type proto}]))
