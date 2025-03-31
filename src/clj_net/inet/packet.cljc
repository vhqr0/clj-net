(ns clj-net.inet.packet
  (:require [clj-bytes.struct :as st]))

(defn enumvar
  [st kimapvar]
  (-> st
      (st/wrap
       #(get (:k->i @kimapvar) % %)
       #(get (:i->k @kimapvar) % %))))

(defmulti parse
  "Parse packet of type from buffer, return parse result
  and remain buffer, or nil if parse failed.
  The parse parse result may contains fields:
  - type: type of packet.
  - data: data of packet.
  - data-extra: extra info of packet, except type and data, eg. parsed options.
  - context-extra: extra info of context.
  - next-info: extra info to parse remain buffer, may contains type and length."
  (fn [type _context _buffer]
    type))

(defmethod parse :default [_type _context _buffer])

(defn parse-packet
  "Parse a packet with specified struct, and an optional
  result-fn to get extra info from data, such as data-extra,
  context-extra or next-info."
  ([st type buffer]
   (parse-packet st type buffer nil))
  ([st type buffer result-fn]
   (when-let [[data buffer] (-> buffer (st/unpack st))]
     (let [result (merge
                   {:type type :data data}
                   (when (some? result-fn)
                     (result-fn data)))]
       [result buffer]))))

(defn parse-option
  "Parse an option, update type and data, if possible."
  ([option type]
   (-> option (assoc :type type)))
  ([option type st]
   (-> option
       (assoc :type type)
       (update :data st/unpack-one st))))
