(ns clj-net.inet.packet
  (:require [clj-lang-extra.core :refer [try-catch]]
            [clj-bytes.core :as b]
            [clj-bytes.struct :as st]))

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

(def ^:dynamic *ex-handler* nil)

(defn parse-layers
  [type context buffer]
  (loop [layers [] trail (b/empty) next-info {:type type} context context buffer buffer]
    (if (b/empty? buffer)
      [layers context]
      (let [{:keys [type length]} next-info
            [buffer trail] (if (or (nil? length) (<= (b/count buffer) length))
                             [buffer trail]
                             (let [[buffer new-trail] (b/split-at! length buffer)]
                               [buffer (b/concat! new-trail trail)]))
            parse-res (when (some? type)
                        (let [[parse-res ex] (try-catch #(parse type context buffer))]
                          (when (and (some? *ex-handler*) (some? ex))
                            (*ex-handler* ex))
                          parse-res))]
        (if (nil? parse-res)
          (let [trail (b/concat! buffer trail)
                layers (cond-> layers
                         (not (b/empty? trail)) (conj {:type :raw :buffer trail}))]
            [layers context])
          (let [[{:keys [type data data-extra context-extra next-info]} buffer] parse-res
                layer (merge {:type type :data data} data-extra)
                context (merge context context-extra)]
            (recur (conj layers layer) trail next-info context buffer)))))))

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
   (let [data (:data option)
         data (let [[unpacked-data ex] (try-catch #(st/unpack-one data st))]
                (when (and (some? *ex-handler*) (some? ex))
                  (*ex-handler* ex))
                (if (some? ex) data unpacked-data))]
     (assoc option :type type :data data))))
