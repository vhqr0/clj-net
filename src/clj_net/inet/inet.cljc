(ns clj-net.inet.inet
  (:require [clj-bytes.core :as b]
            [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]))

;;; ether

;; RFC 1042

(def ether-type-map
  {:arp 0x0806 :ipv4 0x0800 :ipv6 0x86dd})

(def st-ether
  (st/keys
   :dst ia/st-mac
   :src ia/st-mac
   :type st/uint16-be))

;;; arp

;; RFC 826

(def arp-hwtype->int
  {:ether 1})

(def st-arp-hwtype
  (st/enum st/uint16-be arp-hwtype->int))

(def arp-ptype->int
  {:ipv4 0x0800})

(def st-arp-ptype
  (st/enum st/uint16-be arp-ptype->int))

(def arp-op->int
  {:request 1 :reply 2})

(def st-arp-op
  (st/enum st/uint16-be arp-op->int))

(def st-arp
  (st/keys
   :hwtype st-arp-hwtype
   :ptype st-arp-ptype
   :hwlen (-> st/int8 (st/wrap-validator #(= % 6)))
   :plen (-> st/int8 (st/wrap-validator #(= % 4)))
   :op st-arp-op
   :hwsrc ia/st-mac
   :psrc ia/st-ipv4
   :hwdst ia/st-mac
   :pdst ia/st-ipv4))

;;; ip common

(def ip-proto-map
  {:nonxt     59
   :frag      44
   :hbh-opts   0
   :dest-opts 60
   :icmpv4     1
   :icmpv6    58
   :tcp        6
   :udp       17})

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

;;; ipv4

;; RFC 791

(defn ipv4-ihl->oslen
  "Get ipv4 options length."
  [ihl]
  {:pre [(>= ihl 5)]}
  (* 4 (- ihl 5)))

(defn ipv4-oslen->ihl
  "Get ipv4 header length."
  [oslen]
  {:pre [(zero? (mod oslen 4))]}
  (+ (quot oslen 4) 5))

(def st-ipv4
  (-> (st/key-fns
       :version-ihl (constantly (st/bits [4 4]))
       :tos (constantly st/uint8)
       :len (constantly st/uint16-be)
       :id (constantly st/uint16-be)
       :flags-frag (constantly (st/bits [3 13]))
       :ttl (constantly st/uint8)
       :proto (constantly st/uint8)
       :chksum (constantly st/uint8)
       :src (constantly ia/st-ipv4)
       :dst (constantly ia/st-ipv4)
       :options #(st/bytes-fixed (ipv4-ihl->oslen (:ihl %))))
      (st/wrap-vec-destructs
       {:version-ihl [:version :ihl]
        :flags-frag [:flags :frag]})))

(defn ipv4-olen->dlen
  [olen]
  {:pre [(>= olen 2)]}
  (- olen 2))

(defn ipv4-dlen->olen
  [dlen]
  (+ dlen 2))

(def st-ipv4-option-data
  (-> st/uint8
      (st/wrap
       ipv4-dlen->olen
       ipv4-olen->dlen)
      st/bytes-var))

(def st-ipv4-option
  (st/key-fns
   :type (constantly st/uint8)
   :data (fn [{:keys [type]}]
           (case type
             (0 1) (st/bytes-fixed 0)
             st-ipv4-option-data))))

;;; ipv6

;; RFC 8200

(def st-ipv6
  (-> (st/keys
       :version-tc-fl (st/bits [4 8 20])
       :plen st/uint16-be
       :nh st/uint8
       :hlim st/uint8
       :src ia/st-ipv6
       :dst ia/st-ipv4)
      (st/wrap-vec-destructs
       {:version-tc-fl [:version :tc :fl]})))

(defn ipv6-elen->dlen
  [elen]
  (+ 6 (* 8 elen)))

(defn ipv6-dlen->elen
  [dlen]
  {:pre [(zero? (mod (- dlen 6) 8))]}
  (quot (- dlen 6) 8))

(def st-ipv6-ext
  (st/keys
   :nh st/uint8
   :data (-> st/uint8
             (st/wrap
              ipv6-dlen->elen
              ipv6-elen->dlen)
             st/bytes-var)))

(def st-ipv6-ext-frag
  (-> (st/keys
       :nh st/uint8
       :res1 st/uint8
       :offset-m (st/bits [13 2 1])
       :id st/uint32-be)
      (st/wrap-vec-destructs
       {:offset-m [:offset :res2 :m]})))

(def st-ipv6-option-data
  (st/bytes-var st/uint8))

(def st-ipv6-option
  (st/key-fns
   :type (constantly st/uint8)
   :data (fn [{:keys [type]}]
           (case type
             0 (st/bytes-fixed 0)
             st-ipv6-option-data))))

;;; icmpv4

;; RFC 792

(def icmpv4-type-map
  {:echo-reply           0
   :echo-request         8
   :dest-unreach         3
   :source-quench        4
   :redirect             5
   :time-exceeded       11
   :param-problem       12
   :timestamp-request   13
   :timestamp-reply     14
   :information-request 15
   :information-reply   16})

(def icmpv4-redirect-code-map
  {:network-redirect     0
   :host-redirect        1
   :tos-network-redirect 2
   :tos-host-redirect    3})

(def icmpv4-dest-unreach-code-map
  {:network-unreachable  0
   :host-unreachable     1
   :protocol-unreachable 2
   :port-unreachable     3
   :fragmentation-needed 4
   :source-route-failed  5})

(def icmpv4-time-exceeded-code-map
  {:ttl-zero-during-transit    0
   :ttl-zero-during-reassembly 1})

(def icmpv4-param-problem-code-map
  {:ip-header-bad 0})

(def st-icmpv4
  (st/keys
   :type st/uint8
   :code st/uint8
   :chksum st/uint16-be))

;;; icmpv6

;; RFC 4443 ICMPv6
;; RFC 4861 NDP

(def icmpv6-type-map
  {:dest-unreach     1
   :packet-too-big   2
   :time-exceeded    3
   :param-problem    4
   :echo-request   128
   :echo-reply     129
   :nd-rs          133
   :nd-ra          134
   :nd-ns          135
   :nd-na          136
   :redirect       137})

(def icmpv6-dest-unreach-code-map
  {:no-route-to-destination        0
   :administratively-prohibited    1
   :beyond-scope-of-source-address 2
   :address-unreachable            3
   :port-unreachable               4
   :source-address-failed-policy   5
   :reject-route-to-destination    6})

(def icmpv6-time-exceeded-code-map
  {:hop-limit-exceeded-in-transit     0
   :fragment-reassembly-time-exceeded 1})

(def icmpv6-param-problem-code-map
  {:erroneous-header-field-encountered         0
   :unrecognized-next-header-type-encountered  1
   :unrecognized-ipv6-option-encountered       2
   :first-fragment-has-incomplete-header-chain 3})

(def st-icmpv6
  (st/keys
   :type st/uint8
   :code st/uint8
   :chksum st/uint16-be))
