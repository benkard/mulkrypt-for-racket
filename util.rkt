#lang typed/racket
;;; Copyright 2011, Matthias Andreas Benkard.
;;;
;;;-----------------------------------------------------------------------------
;;; This program is free software: you can redistribute it and/or modify
;;; it under the terms of the GNU Affero General Public License as published by
;;; the Free Software Foundation, either version 3 of the License, or
;;; (at your option) any later version.
;;;
;;; This program is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU Affero General Public License for more details.
;;;
;;; You should have received a copy of the GNU Affero General Public License
;;; along with this program.  If not, see <http://www.gnu.org/licenses/>.
;;;-----------------------------------------------------------------------------
;;;

(provide integer->bytes
         integer->bytes/size
         bytes->integer
         pad-bytes
         Justification
         Endianness
         bytes-xor)

(define-type Justification (U 'left 'right))
(define-type Endianness    (U 'little-endian 'big-endian))

(define: (integer->bytes [x          : Exact-Nonnegative-Integer]
                         [endianness : Endianness])
  : Bytes
  (let: loop : Bytes
        ([acc : (Listof Byte) (list)]
         [x : Exact-Nonnegative-Integer x])
    (if (zero? x)
        (list->bytes (if (eq? endianness 'big-endian)
                         acc
                         (reverse acc)))
        (loop (cons (bitwise-and #xff x) acc)
              (arithmetic-shift x -8)))))

(define: (integer->bytes/size [x          : Exact-Nonnegative-Integer]
                              [endianness : Endianness]
                              [size       : Exact-Nonnegative-Integer])
  : Bytes
  (pad-bytes (integer->bytes x endianness)
             size
             #x0
             (if (eq? endianness 'big-endian)
                 'right
                 'left)))

(define: (bytes->integer [b : Bytes]) : Exact-Nonnegative-Integer
  (for/fold: ([n : Exact-Nonnegative-Integer 0])
             ([byte : Byte (in-bytes b)])
    (bitwise-ior (arithmetic-shift n 8)
                 byte)))

(define: (pad-bytes [b : Bytes]
                    [s : Exact-Nonnegative-Integer]
                    [fill : Byte]
                    [justify : Justification])
  : Bytes
  (if (>= (bytes-length b) s)
      b
      (let* ([delta   (- s (bytes-length b))]
             [padding (make-bytes delta fill)])
        (if (eq? justify 'left)
            (bytes-append b padding)
            (bytes-append padding b)))))

(define: (bytes-xor [a : Bytes] [b : Bytes]) : Bytes
  (list->bytes
   (reverse
    (for/fold: ([acc : (Listof Byte) (list)])
               ([x : Byte (in-bytes a)]
                [y : Byte (in-bytes b)])
      (cons (bitwise-xor x y) acc)))))

