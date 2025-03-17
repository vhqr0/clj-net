(ns clj-net.abnf.rfc9111
  (:require [clj-net.abnf :as abnf]
            [clj-net.abnf.rfc9110 :as rfc9110]))

(def rules-text "
Age = delta-seconds

Cache-Control = [ cache-directive *( OWS \",\" OWS cache-directive ) ]

Expires = HTTP-date

;; HTTP-date = <HTTP-date, see [HTTP], Section 5.6.7>

;; OWS = <OWS, see [HTTP], Section 5.6.3>

cache-directive = token [ \"=\" ( token / quoted-string ) ]

delta-seconds = 1*DIGIT

;; field-name = <field-name, see [HTTP], Section 5.1>

;; quoted-string = <quoted-string, see [HTTP], Section 5.6.4>

;; token = <token, see [HTTP], Section 5.6.2>
")

(def refs
  {"http-date" {:type :ref :id "http-date" :rules rfc9110/rules}
   "ows" {:type :ref :id "ows" :rules rfc9110/rules}
   "field-name" {:type :ref :id "field-name" :rules rfc9110/rules}
   "quoted-string" {:type :ref :id "quoted-string" :rules rfc9110/rules}
   "token" {:type :ref :id "token" :rules rfc9110/rules}})

(def rules
  (abnf/compile-rules-text (merge abnf/core-rules refs) rules-text))
