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

(provide integer->bytes)

(define: (integer->bytes [x : Exact-Nonnegative-Integer]) : Bytes
  (let: loop : Bytes
        ([acc : (Listof Byte) (list)]
         [x : Exact-Nonnegative-Integer x])
    (if (zero? x)
        (list->bytes acc)
        (loop (cons (bitwise-and #xff x) acc)
              (arithmetic-shift x -8)))))
