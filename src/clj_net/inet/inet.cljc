(ns clj-net.inet.inet
  (:require [clj-lang-extra.core :refer [try-catch]]
            [clj-bytes.core :as b]
            [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]))

(defmulti parse
  "Parse packet of type, return parsed packet and new context, or nil if parse failed."
  (fn [type _opts _context _buffer] type))

(defn parse-raw
  [context buffer]
  [{:type :raw :buffer buffer} context])

(defmethod parse :default [_type _opts context buffer]
  (parse-raw context buffer))

(defn parse-type-or-raw
  [type opts context buffer]
  (let [[parse-res ex] (try-catch #(parse type opts context buffer))]
    (if (and (nil? ex) (some? parse-res))
      parse-res
      (parse-raw context buffer))))

(defn parse-next
  ([type opts context buffer]
   (if (b/empty? buffer)
     [nil context]
     (if-not (keyword? type)
       (parse-raw context buffer)
       (parse-type-or-raw type opts context buffer))))
  ([type opts context buffer plen]
   (let [[buffer trail-buffer] (if (<= (b/count buffer) plen)
                                 [buffer nil]
                                 (b/split-at! plen buffer))
         [next context] (if-not (= (b/count buffer) plen)
                          (parse-raw context buffer)
                          (parse-next type opts context buffer))]
     [next context trail-buffer])))

;;; ether

;; RFC 1042

(def ether-type-map
  (st/->kimap {:arp 0x0806 :ipv4 0x0800 :ipv6 0x86dd}))

(def st-ether
  (st/keys
   :dst ia/st-mac
   :src ia/st-mac
   :type st/uint16-be))

(defmethod parse :ether [_type {:ether/keys [type-map] :as opts} context buffer]
  (when-let [[{:keys [dst src type] :as st} buffer] (-> buffer (st/unpack st-ether))]
    (let [type (get-in type-map [:i->k type] type)
          context (merge context #:ether{:type type :dst dst :src src})
          [next context] (parse-next type opts context buffer)
          packet (cond-> {:type :ether :st st :src src :dst dst}
                   (keyword? type) (assoc :next-type type)
                   (some? next) (assoc :next-packet next))]
      [packet context])))

;;; arp

;; RFC 826

(def arp-hwtype-map
  (st/->kimap {:ether 1}))

(def st-arp-hwtype
  (st/enum st/uint16-be arp-hwtype-map))

(def arp-ptype-map
  (st/->kimap {:ipv4 0x0800}))

(def st-arp-ptype
  (st/enum st/uint16-be arp-ptype-map))

(def arp-op-map
  (st/->kimap {:request 1 :reply 2}))

(def st-arp-op
  (st/enum st/uint16-be arp-op-map))

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

(defmethod parse :arp [_type _opts context buffer]
  (when-let [[{:keys [op hwsrc psrc hwdst pdst] :as st} buffer]
             (-> buffer (st/unpack st-arp))]
    (let [context (merge context #:arp{:op op})
          [next context] (if (b/empty? buffer)
                           [nil context]
                           (parse-raw context buffer))
          packet (cond-> {:type :arp :st st :op op :src [hwsrc psrc] :dst [hwdst pdst]}
                   (some? next) (assoc :next-packet next))]
      [packet context])))

;;; ip common

(def ip-proto-map
  (st/->kimap
   {:ipv6-no-next       59
    :ipv6-ext-fragment  44
    :ipv6-ext-hbh-opts   0
    :ipv6-ext-dest-opts 60
    :icmpv4              1
    :icmpv6             58
    :tcp                 6
    :udp                17}))

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

(defmethod parse :ip [_type opts context buffer]
  (when-not (b/empty? buffer)
    (let [version (-> (b/uget buffer 0) (bit-shift-right 4))]
      (case version
        4 (parse :ipv4 opts context buffer)
        6 (parse :ipv6 opts context buffer)))))

;;; ipv4

;; RFC 791

(def st-ipv4
  (-> (st/key-fns
       :version-ihl (constantly (st/bits [4 4]))
       :tos (constantly st/uint8)
       :len (constantly st/uint16-be)
       :id (constantly st/uint16-be)
       :res-df-mf-frag (constantly (st/bits [1 1 1 13]))
       :ttl (constantly st/uint8)
       :proto (constantly st/uint8)
       :chksum (constantly st/uint8)
       :src (constantly ia/st-ipv4)
       :dst (constantly ia/st-ipv4)
       :options #(st/bytes-fixed (* 4 (- (:ihl %) 5))))
      (st/wrap-vec-destructs
       {:version-ihl [:version :ihl]
        :res-df-mf-frag [:res :df :mf :frag]})))

(def ipv4-option-map
  (st/->kimap {:eol 0 :nop 1}))

(def st-ipv4-option
  (st/key-fns
   :type (constantly st/uint8)
   :data (fn [{:keys [type]}]
           (case type
             (0 1) (st/bytes-fixed 0)
             (-> st/uint8
                 (st/wrap #(+ % 2) #(- % 2))
                 st/bytes-var)))))

(defmethod parse :ipv4 [_type {:ip/keys [proto-map] :as opts} context buffer]
  (when-let [[{:keys [proto src dst ihl plen] :as st} buffer]
             (-> buffer (st/unpack st-ipv4))]
    (let [plen (- plen (* 5 ihl))
          proto (get-in proto-map [:i->k proto] proto)
          context (merge context #:ip{:version 4 :proto proto :src src :dst dst :plen plen})
          [next context trail-buffer] (parse-next proto opts context buffer plen)
          packet (cond-> {:type :ipv4 :st st :src src :dst dst :plen plen}
                   (some? trail-buffer) (assoc :trail-buffer trail-buffer)
                   (keyword? proto) (assoc :next-type proto)
                   (some? next) (assoc :next-packet next))]
      [packet context])))

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

(def st-ipv6-ext
  (st/keys
   :nh st/uint8
   :data (-> st/uint8
             (st/wrap-validator
              #(zero? (mod (- % 6) 8)))
             (st/wrap
              #(quot (- % 6) 8)
              #(+ 6 (* 8 %)))
             st/bytes-var)))

(def st-ipv6-ext-fragment
  (-> (st/keys
       :nh st/uint8
       :res1 st/uint8
       :offset-res2-m (st/bits [13 2 1])
       :id st/uint32-be)
      (st/wrap-vec-destructs
       {:offset-res2-m [:offset :res2 :m]})))

(def ipv6-option-map
  (st/->kimap {:pad1 0 :padn 1}))

(def st-ipv6-option
  (st/key-fns
   :type (constantly st/uint8)
   :data (fn [{:keys [type]}]
           (case type
             0 (st/bytes-fixed 0)
             (st/bytes-var st/uint8)))))

(defmethod parse :ipv6 [_type {:ip/keys [proto-map] :as opts} context buffer]
  (when-let [[{:keys [nh src dst plen] :as st} buffer]
             (-> buffer (st/unpack st-ipv4))]
    (let [proto (get-in proto-map [:i->k nh] nh)
          context (merge context #:ip{:version 6 :proto proto :src src :dst dst :plen plen})
          [next context trail-buffer] (parse-next proto opts context buffer plen)
          packet (cond-> {:type :ipv6 :st st :src src :dst dst :plen plen}
                   (some? trail-buffer) (assoc :trail-buffer trail-buffer)
                   (keyword? proto) (assoc :next-type proto)
                   (some? next) (assoc :next-packet next))]
      [packet context])))

(defn parse-ipv6-ext [type {:ip/keys [proto-map] :as opts} context buffer]
  (when-let [[{:keys [nh] :as st} buffer] (-> buffer (st/unpack st-ipv6-ext))]
    (let [proto (get-in proto-map [:i->k nh] nh)
          [next context] (parse-next proto opts context buffer)
          packet (cond-> {:type type :st st}
                   (keyword? proto) (assoc :next-type proto)
                   (some? next) (assoc :next-packet next))]
      [packet context])))

(defmethod parse :ipv6-ext-hbh-opts [type opts context buffer]
  (parse-ipv6-ext type opts context buffer))

(defmethod parse :ipv6-ext-dest-opts [type opts context buffer]
  (parse-ipv6-ext type opts context buffer))

(defmethod parse :ipv6-ext-fragment [_type {:ip/keys [proto-map]} context buffer]
  (when-let [[{:keys [nh] :as st} buffer] (-> buffer (st/unpack st-ipv6-ext-fragment))]
    (let [proto (get-in proto-map [:i->k nh] nh)
          [next context] (parse-raw context buffer)
          packet (cond-> {:type :ipv6-ext-fragment :st st}
                   (keyword? proto) (assoc :next-type proto)
                   (some? next) (assoc :next-packet next))]
      [packet context])))

;;; icmpv4

;; RFC 792

(def icmpv4-type-map
  (st/->kimap
   {:icmpv4-echo-reply           0
    :icmpv4-echo-request         8
    :icmpv4-dest-unreach         3
    :icmpv4-source-quench        4
    :icmpv4-redirect             5
    :icmpv4-time-exceeded       11
    :icmpv4-param-problem       12
    :icmpv4-timestamp-request   13
    :icmpv4-timestamp-reply     14
    :icmpv4-information-request 15
    :icmpv4-information-reply   16}))

(def icmpv4-redirect-code-map
  (st/->kimap
   {:network-redirect     0
    :host-redirect        1
    :tos-network-redirect 2
    :tos-host-redirect    3}))

(def icmpv4-dest-unreach-code-map
  (st/->kimap
   {:network-unreachable  0
    :host-unreachable     1
    :protocol-unreachable 2
    :port-unreachable     3
    :fragmentation-needed 4
    :source-route-failed  5}))

(def icmpv4-time-exceeded-code-map
  (st/->kimap
   {:ttl-zero-during-transit    0
    :ttl-zero-during-reassembly 1}))

(def icmpv4-param-problem-code-map
  (st/->kimap {:ip-header-bad 0}))

(def st-icmpv4
  (st/keys
   :type st/uint8
   :code st/uint8
   :chksum st/uint16-be))

(def st-icmpv4-echo
  (st/keys
   :id st/uint16-be
   :seq st/uint16-be))

(def st-icmpv4-redirect
  (st/keys
   :gw ia/st-ipv4))

(defmethod parse :icmpv4 [_type {:icmpv4/keys [type-map] :as opts} context buffer]
  (when-let [[{:keys [type code] :as st} buffer] (-> buffer (st/unpack st-icmpv4))]
    (let [type (get-in type-map [:i->k type] type)
          context (merge context #:icmpv4{:type type :code code})
          [next context] (parse-next type opts context buffer)
          packet (cond-> {:type :icmpv4 :st st :code code}
                   (keyword? type) (assoc :next-type type)
                   (some? next) (assoc :next-packet next))]
      [packet context])))

(defn parse-icmpv4-echo
  [type context buffer]
  (when-let [[{:keys [seq id] :as st} buffer] (-> buffer (st/unpack st-icmpv4-echo))]
    (let [context (merge context #:icmpv4{:seq seq :id id})
          [next context] (parse-raw context buffer)
          packet (cond-> {:type type :st st :id id :seq seq}
                   (some? next) (assoc :next-packet next))]
      [packet context])))

(defmethod parse :icmpv4-echo-request [type _opts context buffer]
  (parse-icmpv4-echo type context buffer))

(defmethod parse :icmpv4-echo-reply [type _opts context buffer]
  (parse-icmpv4-echo type context buffer))

(defmethod parse :icmpv4-redirect [_type _opts context buffer]
  (when-let [[{:keys [gw] :as st} buffer] (-> buffer (st/unpack st-icmpv4-redirect))]
    (let [[next context] (parse-raw context buffer)
          packet (cond-> {:type :icmpv4-redirect :st st :gw gw}
                   (some? next) (assoc :next-packet next))]
      [packet context])))

;;; icmpv6

;; RFC 4443 ICMPv6
;; RFC 4861 NDP

(def icmpv6-type-map
  (st/->kimap
   {:icmpv6-dest-unreach     1
    :icmpv6-packet-too-big   2
    :icmpv6-time-exceeded    3
    :icmpv6-param-problem    4
    :icmpv6-echo-request   128
    :icmpv6-echo-reply     129
    :icmpv6-nd-rs          133
    :icmpv6-nd-ra          134
    :icmpv6-nd-ns          135
    :icmpv6-nd-na          136
    :icmpv6-nd-redirect    137}))

(def icmpv6-dest-unreach-code-map
  (st/->kimap
   {:no-route-to-destination        0
    :administratively-prohibited    1
    :beyond-scope-of-source-address 2
    :address-unreachable            3
    :port-unreachable               4
    :source-address-failed-policy   5
    :reject-route-to-destination    6}))

(def icmpv6-time-exceeded-code-map
  (st/->kimap
   {:hop-limit-exceeded-in-transit     0
    :fragment-reassembly-time-exceeded 1}))

(def icmpv6-param-problem-code-map
  (st/->kimap
   {:erroneous-header-field-encountered         0
    :unrecognized-next-header-type-encountered  1
    :unrecognized-ipv6-option-encountered       2
    :first-fragment-has-incomplete-header-chain 3}))

(def st-icmpv6
  (st/keys
   :type st/uint8
   :code st/uint8
   :chksum st/uint16-be))

(def st-icmpv6-echo
  (st/keys
   :id st/uint16-be
   :seq st/uint16-be))

(def st-icmpv6-packet-too-big
  (st/keys
   :mtu st/uint32-be))

(def st-icmpv6-nd-rs
  (st/keys
   :res st/uint32-be
   :options st/bytes))

(def st-icmpv6-nd-ra
  (-> (st/keys
       :chlim st/uint8
       :m-o-res (st/bits [1 1 6])
       :routerlifetime st/uint16-be
       :reachabletime st/uint32-be
       :retranstimer st/uint32-be
       :options st/bytes)
      (st/wrap-vec-destructs
       {:m-o-res [:m :o :res]})))

(def st-icmpv6-nd-ns
  (st/keys
   :res st/uint32-be
   :tgt ia/st-ipv6
   :options st/bytes))

(def st-icmpv6-nd-na
  (-> (st/keys
       :r-s-o-res (st/bits [1 1 1 13])
       :tgt ia/st-ipv6
       :options st/bytes)
      (st/wrap-vec-destructs
       {:r-s-o-res [:r :s :o :res]})))

(def st-icmpv6-nd-redirect
  (st/keys
   :res st/uint32-be
   :tgt ia/st-ipv6
   :dst ia/st-ipv6
   :options st/bytes))

(def icmpv6-nd-option-map
  (st/->kimap
   {:src-lladdr   1
    :dst-lladdr   2
    :prefix-info  3
    :redirect-hdr 4
    :mtu          5}))

(def st-icmpv6-nd-option
  (st/keys
   :type st/uint8
   :data (-> st/uint8
             (st/wrap #(+ % 2) #(- % 2))
             st/bytes-var)))

(def st-icmpv6-nd-option-lladdr
  ia/st-mac)

(def st-icmpv6-nd-option-prefix-info
  (-> (st/keys
       :prefixlen st/uint8
       :l-a-res1 (st/bits [1 1 6])
       :validlifetime st/uint32-be
       :preferredlifetime st/uint32-be
       :res2 st/uint32-be
       :prefix ia/st-ipv6)
      (st/wrap-vec-destructs
       {:l-a-res1 [:l :a :res1]})))

(def st-icmpv6-nd-option-redirect-hdr
  (st/keys
   :res1 st/uint16-be
   :res2 st/uint32-be
   :pkt st/bytes))

(def st-icmpv6-nd-option-mtu
  (st/keys
   :res st/uint16-be
   :mtu st/uint32-be))

(defmethod parse :icmpv6 [_type {:icmpv6/keys [type-map] :as opts} context buffer]
  (when-let [[{:keys [type code] :as st} buffer] (-> buffer (st/unpack st-icmpv6))]
    (let [type (get-in type-map [:i->k type] type)
          context (merge context #:icmpv4{:type type :code code})
          [next context] (parse-next type opts context buffer)
          packet (cond-> {:type :icmpv6 :st st :code code}
                   (keyword? type) (assoc :next-type type)
                   (some? next) (assoc :next-packet next))]
      [packet context])))

(defn parse-icmpv6-echo
  [type context buffer]
  (when-let [[{:keys [seq id] :as st} buffer] (-> buffer (st/unpack st-icmpv4-echo))]
    (let [context (merge context #:icmpv4{:seq seq :id id})
          [next context] (parse-raw context buffer)
          packet (cond-> {:type type :st st :id id :seq seq}
                   (some? next) (assoc :next-packet next))]
      [packet context])))

(defmethod parse :icmpv6-echo-request [type _opts context buffer]
  (parse-icmpv6-echo type context buffer))

(defmethod parse :icmpv6-echo-reply [type _opts context buffer]
  (parse-icmpv6-echo type context buffer))

(defmethod parse :icmpv6-packet-too-big [_type _opts context buffer]
  (when-let [[{:keys [mtu] :as st} buffer] (-> buffer (st/unpack st-icmpv6-packet-too-big))]
    (let [[next context] (parse-raw context buffer)
          packet (cond-> {:type :icmpv6-packet-too-big :st st :mtu mtu}
                   (some? next) (assoc :next-packet next))]
      [packet context])))

(defmethod parse :icmpv6-nd-rs [_type _opts context buffer]
  (when-let [[st buffer] (-> buffer (st/unpack st-icmpv6-nd-rs))]
    (let [[next context] (parse-raw context buffer)
          packet (cond-> {:type :icmpv6-nd-rs :st st}
                   (some? next) (assoc :next-packet next))]
      [packet context])))

(defmethod parse :icmpv6-nd-ra [_type _opts context buffer]
  (when-let [[st buffer] (-> buffer (st/unpack st-icmpv6-nd-ra))]
    (let [[next context] (parse-raw context buffer)
          packet (cond-> {:type :icmpv6-nd-ra :st st}
                   (some? next) (assoc :next-packet next))]
      [packet context])))

(defmethod parse :icmpv6-nd-ns [_type _opts context buffer]
  (when-let [[{:keys [tgt] :as st} buffer] (-> buffer (st/unpack st-icmpv6-nd-ns))]
    (let [[next context] (parse-raw context buffer)
          packet (cond-> {:type :icmpv6-nd-ns :st st :tgt tgt}
                   (some? next) (assoc :next-packet next))]
      [packet context])))

(defmethod parse :icmpv6-nd-na [_type _opts context buffer]
  (when-let [[{:keys [tgt] :as st} buffer] (-> buffer (st/unpack st-icmpv6-nd-na))]
    (let [[next context] (parse-raw context buffer)
          packet (cond-> {:type :icmpv6-nd-na :st st :tgt tgt}
                   (some? next) (assoc :next-packet next))]
      [packet context])))

(defmethod parse :icmpv6-nd-redirect [_type _opts context buffer]
  (when-let [[{:keys [tgt dst] :as st} buffer] (-> buffer (st/unpack st-icmpv6-nd-redirect))]
    (let [[next context] (parse-raw context buffer)
          packet (cond-> {:type :icmpv6-nd-redirect :st st :tgt tgt :dst dst}
                   (some? next) (assoc :next-packet next))]
      [packet context])))

;;; udp

;; RFC 768

(def udp-port-map
  (st/->kimap
   {:dns            53
    :dhcpv4-client  67
    :dhcpv6-sever   68
    :dhcpv6-client 546
    :dhcpv6-server 547}))

(def st-udp
  (st/keys
   :sport st/uint16-be
   :dport st/uint16-be
   :len st/uint16-be
   :chksum st/uint16-be))

;;; tcp

;; RFC 9293 TCP
;; RFC 7323 TCP extensions
;; RFC 2018 TCP sack

(def st-tcp
  (-> (st/key-fns
       :sport (constantly st/uint16-be)
       :dport (constantly st/uint16-be)
       :seq (constantly st/uint32-be)
       :ack (constantly st/uint32-be)
       :dtaofs-reserved (constantly (st/bits [4 4]))
       :cwr-ece-urg-ack-psh-rst-syn-fin (constantly (st/bits [1 1 1 1 1 1 1 1]))
       :window (constantly st/uint16-be)
       :chksum (constantly st/uint16-be)
       :urgptr (constantly st/uint16-be)
       :options #(st/bytes-fixed (* 4 (- (:dataofs %) 5))))
      (st/wrap-vec-destructs
       {:dataofs-reserved [:dataofs :reserved]
        :cwr-ece-urg-ack-psh-rst-syn-fin [:cwr :ece :urg :ack :psh :rst :syn :fin]})))

(def st-tcp-option
  (st/key-fns
   :type (constantly st/uint8)
   :data (fn [{:keys [type]}]
           (case type
             (0 1) (st/bytes-fixed 0)
             (-> st/uint8
                 (st/wrap #(+ % 2) #(- % 2))
                 st/bytes-var)))))

(def tcp-option-map
  (st/->kimap {:eol 0 :nop 1 :mss 2 :wscale 3 :sack-ok 4 :sack 5 :timestamp 6}))

(def tcp-option-mss
  st/uint16-be)

(def tcp-option-wscale
  st/uint8)

(def tcp-option-sack
  (st/coll-of st/uint32-be))

(def tcp-option-timestamp
  (st/keys
   :tsval st/uint32-be
   :tsecr st/uint16-be))
