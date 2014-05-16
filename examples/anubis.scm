;;;
;;; anubis.scm
;;;
;;; This file is part of GNU Anubis.
;;; Copyright (C) 2003-2014 The Anubis Team.
;;;
;;; GNU Anubis is free software; you can redistribute it and/or modify it
;;; under the terms of the GNU General Public License as published by the
;;; Free Software Foundation; either version 3 of the License, or (at your
;;; option) any later version.
;;;
;;; GNU Anubis is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License along
;;; with GNU Anubis.  If not, see <http://www.gnu.org/licenses/>.

(define debug-level 0)

(define (DEBUG level . rest)
  (if (>= debug-level level)
      (with-output-to-port
	  (current-error-port)
	(lambda ()
	  (display "DEBUG(")
	  (display level)
	  (display "):")
	  (for-each (lambda (x)
		      (display x))
		    rest)
	  (newline)))))

;;; The function below illustrates the concept of Anubis message
;;; processing functions.
;;; A processing function takes two required and any number of
;;; optional arguments. The required arguments are:
;;;
;;;   HDR   -- A list of message headers. Each list element is a cons
;;;            (NAME . VALUE), where NAME is the name of the header field,
;;;            and VALUE is its VALUE with final CRLF stripped off.
;;;   BODY  -- The message body.
;;;
;;; The rest of arguments are collected from the invocation string in
;;; the configuration file and passed to the function.
;;;
;;; The function is expected to return cons:
;;;
;;;     (NEW-HDR . NEW-BODY)
;;;
;;; where
;;;   NEW-HDR is the new header list, or #t to indicate that the headers
;;;   are not changed.
;;;   NEW-BODY is a string representing the new body or a boolean with
;;;   the following meaning:
;;;     #f  --  delete entire body.
;;;     #t  --  preserve the body as is. 

(define (sample-process-message hdr body . rest)
  "If the Subject: field starts with characters \"ODP:\", replace
them with \"Re:\".

If REST is not empty, append its car to BODY"

  (DEBUG 1 "rewrite-subject called with hdr=" hdr " and body=\"" body "\"")
  (DEBUG 2 "optional args=" rest)
  (cons (append
	 (map (lambda (x)
		(if (and (string-ci=? (car x) "subject")
			 (string-ci=? (substring (cdr x) 0 4) "ODP:"))
		    (cons (car x)
			  (string-append "Re:"
					 (substring (cdr x) 4)))
		    x))
	      hdr)
	 (list (cons "X-Processed-By" "GNU Anubis")))
	(if (null? rest)
	    #t
	    (string-append body "\n" (car rest)))))

;; To test your output redirection:
(DEBUG 1 "LOADED anubis.scm")

