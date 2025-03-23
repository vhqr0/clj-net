(ns clj-net.inet.dhcpv4
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]
            [clj-net.inet.dns :as dns]))

;; RFC 2131 DHCPv4
;; RFC 2132 DHCPv4 options

(def dhcpv4-op->int
  {:boot-request 1 :boot-reply 2})

(def st-dhcpv4-op
  (st/enum st/uint8 dhcpv4-op->int))

(def dhcpv4-htype->int
  {:ether 1})

(def st-dhcpv4-htype
  (st/enum st/uint8 dhcpv4-htype->int))

(def dhcpv4-magic 0x63825363)

(def st-dhcpv4
  (st/keys
   :op st-dhcpv4-op
   :htype st-dhcpv4-htype
   :hlen (-> st/uint8 (st/wrap-validator #(= % 6)))
   :hops st/uint8
   :xid st/uint32-be
   :secs st/uint16-be
   :flags st/uint16-be
   :ciaddr ia/st-ipv4
   :yiaddr ia/st-ipv4
   :siaddr ia/st-ipv4
   :giaddr ia/st-ipv4
   :chaddr (st/bytes-fixed 16)
   :sname (st/bytes-fixed 64)
   :file (st/bytes-fixed 128)
   :magic (-> st/uint32-be (st/wrap-validator #(= % dhcpv4-magic)))
   :options st/bytes))

(def st-dhcpv4-message-type->int
  {:discover 1
   :offer    2
   :request  3
   :decline  4
   :ack      5
   :nak      6
   :release  7
   :inform   8})

(def st-dhcpv4-message-type
  (st/enum st/uint8 st-dhcpv4-message-type->int))

(def st-dhcpv4-option-map
  {:end                        255
   :pad                          0
   :subnet-mask                  1
   :time-zone                    2
   :router                       3
   :time-server                  4
   :ien-name-server              5
   :name-server                  6
   :log-server                   7
   :cookie-server                8
   :lpr-server                   9
   :impress-servers             10
   :resource-location-servers   11
   :hostname                    12
   :boot-size                   13
   :dump-path                   14
   :domain                      15
   :swap-server                 16
   :root-disk-path              17
   :extensions-path             18
   :ip-forwarding               19
   :non-local-source-routing    20
   :policy-filter               21
   :max-dgram-reass-size        22
   :default-ttl                 23
   :pmtu-timeout                24
   :path-mtu-plateau-table      25
   :interface-mtu               26
   :all-subnets-local           27
   :broadcast-address           28
   :perform-mask-discovery      29
   :mask-supplier               30
   :router-discovery            31
   :router-solicitation-address 32
   :static-routes               33
   :trailer-encapsulation       34
   :arp-cache-timeout           35
   :ieee802-3-encapsulation     36
   :tcp-ttl                     37
   :tcp-keepalive-interval      38
   :tcp-keepalive-garbage       39
   :nis-domain                  40
   :nis-server                  41
   :ntp-server                  42
   :vendor-specific             43
   :netbios-server              44
   :netbios-dist-server         45
   :netbios-node-type           46
   :netbios-scope               47
   :font-servers                48
   :x-display-manager           49
   :requested-addr              50
   :lease-time                  51
   :dhcp-option-overload        52
   :message-type                53
   :server-id                   54
   :param-req-list              55
   :error-message               56
   :max-dhcp-size               57
   :renewal-time                58
   :rebinding-time              59
   :vendor-class-id             60
   :client-id                   61})

(def st-dhcpv4-option
  (st/keys
   :type st/uint8
   :data (st/bytes-var st/uint8)))

(def st-dhcpv4-option-subnet-mask
  ia/st-ipv4)

(def st-dhcpv4-option-name-server
  (st/coll-of ia/st-ipv4))

(def st-dhcpv4-option-hostname
  dns/st-dns-name)

(def st-dhcpv4-option-domain
  st/str)

(def st-dhcpv4-option-mtu
  st/uint16-be)

(def st-dhcpv4-option-broadcast-address
  ia/st-ipv4)

(def st-dhcpv4-option-ntp-server
  (st/coll-of ia/st-ipv4))

(def st-dhcpv4-option-requested-addr
  ia/st-ipv4)

(def st-dhcpv4-option-lease-time
  st/uint32-be)

(def st-dhcpv4-option-message-type
  st-dhcpv4-message-type)

(def st-dhcpv4-option-server-id
  ia/st-ipv4)

(def st-dhcpv4-option-req-list
  (st/coll-of st/uint8))

(def st-dhcpv4-option-renewal-time
  st/uint32-be)

(def st-dhcpv4-option-rebinding-time
  st/uint32-be)
