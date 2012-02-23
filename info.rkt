#lang setup/infotab
(define name "Mulkrypt")

(define blurb
  '(p ()
      "A pure-Racket, no-dependencies library of cryptographic algorithms. "
      "Implements "
      (a ((href "https://en.wikipedia.org/wiki/HMAC"))
         "HMAC")
      ", the cryptographic hashing functions "
      (a ((href "http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html"))
         "Whirlpool")
      " and "
      (a ((href "http://cubehash.cr.yp.to/"))
         "CubeHash")
      ", and the stream cipher "
      (a ((href "http://cr.yp.to/snuffle.html"))
         "Salsa20")
      "."))
(define categories '(misc))
(define version "1.0")
(define can-be-loaded-with 'all)
(define primary-file "main.rkt")
(define homepage "https://matthias.benkard.de/software/mulkrypt")
;;(define scribblings '(("manual.scrbl" ())))
