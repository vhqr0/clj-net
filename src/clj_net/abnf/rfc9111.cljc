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
  (-> {}
      (abnf/refer-to "HTTP-date" rfc9110/rules)
      (abnf/refer-to "OWS" rfc9110/rules)
      (abnf/refer-to "field-name" rfc9110/rules)
      (abnf/refer-to "quoted-string" rfc9110/rules)
      (abnf/refer-to "token" rfc9110/rules)))

(def rules
  (abnf/compile-rules-text (merge abnf/core-rules refs) rules-text))
