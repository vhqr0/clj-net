(ns clj-net.inet.dhcpv6
  (:require [clj-bytes.core :as b]
            [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]
            [clj-net.inet.packet :as pkt]
            [clj-net.inet.dns :as dns]))

;; RFC 8415 DHCPv6
;; RFC 3646 DHCPv6 DNS options
;; RFC 4075 DHCPv6 SNTP options

(def dhcpv6-msg-type-map
  (st/->kimap
   {:solicit              1
    :advertise            2
    :request              3
    :confirm              4
    :renew                5
    :rebind               6
    :reply                7
    :release              8
    :decline              9
    :reconfigure         10
    :information-request 11
    :relay-forw          12
    :relay-repl          13}))

(def dhcpv6-duid-type-map
  (st/->kimap {:llt 1 :en 2 :ll 3 :uuid 4}))

(def dhcpv6-status-code-map
  (st/->kimap
   {:success         0
    :unspec-fail     1
    :no-addrs-avail  2
    :no-binding      3
    :not-on-link     4
    :use-multicast   5
    :no-prefix-avail 6}))

(def st-dhcpv6-relay
  (-> (st/keys
       :hopcount st/uint8
       :linkaddr ia/st-ipv6
       :peeraddr ia/st-ipv6)
      (st/wrap-merge
       {:hopcount 0 :linkaddr ia/ipv6-zero :peeraddr ia/ipv6-zero})))

(def st-dhcpv6
  (-> (st/keys
       :msg-type st/uint8
       :trid (st/lazy
              (fn [{:keys [msg-type]}]
                (case msg-type
                  (12 13) st-dhcpv6-relay
                  (st/bytes-fixed 3))))
       :options st/bytes)
      (st/wrap-merge
       {:msg-type :solicit :trid (b/make 3) :options (b/empty)})))

(def st-dhcpv6-duid-llt
  (st/keys
   :type (-> st/uint8 (st/wrap-validator #(= % 1)))
   :hwtype st/uint16-be
   :timeval st/uint32-be
   :lladdr ia/st-mac))

(def st-dhcpv6-duid-ll
  (st/keys
   :type (-> st/uint8 (st/wrap-validator #(= % 3)))
   :hwtype st/uint16-be
   :lladdr ia/st-mac))

(def dhcpv6-option-map
  (st/->kimap
   {:client-id             1
    :server-id             2
    :ia-na                 3
    :ia-ta                 4
    :iaaddress             5
    :opt-req               6
    :pref                  7
    :elapsed-time          8
    :relay-msg             9
    :auth                 11
    :server-unicast       12
    :status-code          13
    :rapid-commit         14
    :user-class           15
    :vendor-class         16
    :vendor-specific-info 17
    :iface-id             18
    :reconf-msg           19
    :reconf-accept        20
    :sip-domains          21
    :sip-servers          22
    :dns-servers          23
    :dns-domains          24
    :ia-pd                25
    :iaprefix             26
    :ntp-server           56
    :nis-servers          27
    :nisp-servers         28
    :nis-domain           29
    :nisp-domain          30
    :sntp-servers         31
    :info-refresh-time    32
    :sol-max-rt           82
    :inf-max-rt           83}))

(def st-dhcpv6-option
  (st/keys
   :type st/uint16-be
   :data (st/bytes-var st/uint16-be)))

(def st-dhcpv6-option-ia-na
  (st/keys
   :iaid st/uint32-be
   :t1 st/uint32-be
   :t2 st/uint32-be
   :options st/bytes))

(def st-dhcpv6-option-ia-ta
  (st/keys
   :iaid st/uint32-be
   :options st/bytes))

(def st-dhcpv6-option-iaaddress
  (st/keys
   :addr ia/st-ipv6
   :preflft st/uint32-be
   :validlft st/uint32-be
   :options st/bytes))

(def st-dhcpv6-option-opt-req
  (st/coll-of st/uint16-be))

(def st-dhcpv6-option-pref
  st/uint8)

(def st-dhcpv6-option-elapsed-time
  st/uint16-be)

(def st-dhcpv6-option-server-unicast
  ia/st-ipv6)

(def st-dhcpv6-option-status-code
  (st/keys
   :statuscode st/uint16-be
   :statusmsg st/str))

(def st-dhcpv6-option-reconf-msg
  st/uint8)

(def st-dhcpv6-option-ia-pd
  (st/keys
   :iaid st/uint32-be
   :t1 st/uint32-be
   :t2 st/uint32-be
   :options st/bytes))

(def st-dhcpv6-option-iaprefix
  (st/keys
   :preflft st/uint32-be
   :validlft st/uint32-be
   :plen st/uint8
   :prefix ia/st-ipv6
   :options st/bytes))

(def st-dhcpv6-option-info-refresh-time
  st/uint32-be)

(def st-dhcpv6-option-dns-servers
  (st/coll-of ia/st-ipv6))

(def st-dhcpv6-option-dns-domains
  (st/coll-of dns/st-dns-name))

(def st-dhcpv6-option-sntp-servers
  (st/coll-of ia/st-ipv6))

(def dhcpv6-option-st-map
  {:ia-na st-dhcpv6-option-ia-na
   :ia-ta st-dhcpv6-option-ia-ta
   :iaaddress st-dhcpv6-option-iaaddress
   :opt-req st-dhcpv6-option-opt-req
   :pref st-dhcpv6-option-pref
   :elapsed-time st-dhcpv6-option-elapsed-time
   :server-unicast st-dhcpv6-option-server-unicast
   :status-code st-dhcpv6-option-status-code
   :reconf-msg st-dhcpv6-option-reconf-msg
   :ia-pd st-dhcpv6-option-ia-pd
   :iaprefix st-dhcpv6-option-iaprefix
   :info-refresh-time st-dhcpv6-option-info-refresh-time
   :dns-servers st-dhcpv6-option-dns-servers
   :dns-domain st-dhcpv6-option-dns-domains
   :sntp-servers st-dhcpv6-option-sntp-servers})

(defmulti parse-dhcpv6-option
  (fn [option] (:type option)))

(defmethod parse-dhcpv6-option :default [option] option)

(doseq [[k i] (:k->i dhcpv6-option-map)]
  (let [st (get dhcpv6-option-st-map k)]
    (defmethod parse-dhcpv6-option i [option] (pkt/unpack-option st k option))))

(defmethod pkt/parse :dhcpv6 [type _context buffer]
  (pkt/unpack-packet
   st-dhcpv6 type buffer
   (fn [{:keys [options]}]
     (let [options (->> (st/unpack-many options st-dhcpv6-option) (mapv parse-dhcpv6-option))]
       {:data-extra {:options options}}))))

(defmethod pkt/parse :dhcpv6-client [_type context buffer] (pkt/parse :dhcpv6 context buffer))
(defmethod pkt/parse :dhcpv6-server [_type context buffer] (pkt/parse :dhcpv6 context buffer))
