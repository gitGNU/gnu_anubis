# This file is part of GNU Anubis testsuite.
# Copyright (C) 2003 The Anubis Team.
#
# GNU Anubis is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# GNU Anubis is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Anubis; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

:TEST parse
:MODE EXEC
:OPTIONS --check-config
:RCFILE std.rc
:RETCODE 0
:PATTERN
BEGIN SECTION CONTROL
  ASGN: logfile = anubis.log
  ASGN: remote-mta = localhost:25
  ASGN: ssl = yes
END SECTION CONTROL
BEGIN SECTION RULE
  ASGN: gpg-passphrase = MYSECRETPASSPHRASE
  REMOVE HEADER :exact [Lines]
  COND: COMMAND[mail from] :posix [.*<?root@localhost>?]
  IFTRUE:
    STOP
  END COND
  COND: AND (HEADER[Subject] :posix [(.*)],NOT (HEADER[Subject] :posix :scase [URGENT]))
  IFTRUE:
    ADD HEADER[X-Comment] "This message is not URGENT (\1)."
    ADD HEADER[X-Comment] "GNU's Not Unix! (\1)"
  END COND
  COND: HEADER[X-Mailer] :posix [(.*)]
  IFTRUE:
    ADD HEADER[X-Comment] "My love \1"
    MODIFY HEADER :exact [X-Mailer] "The lousy mailer \1"
  END COND
  RULE: HEADER :posix [gpgd:(.*)]
  BODY
    ADD HEADER[X-GPG-Comment] "Encrypted for \1"
    ASGN: gpg-encrypt = \1
  END RULE
  COND: HEADER[Subject] :posix [signature]
  IFTRUE:
    ASGN: signature-file-append = yes
  END COND
  COND: HEADER[Subject] :posix :scase [external]
  IFTRUE:
    ASGN: external-body-processor = /usr/bin/formail
  END COND
  COND: HEADER[Subject] :posix [gpg-all]
  IFTRUE:
    ASGN: gpg-encrypt = USERNAME
    ASGN: gpg-sign = yes
  END COND
  COND: HEADER[Subject] :posix [gpg-encrypt]
  IFTRUE:
    ASGN: gpg-encrypt = USERNAME-1,USERNAME-2,USERNAME-3
  END COND
  COND: HEADER[Subject] :posix [gpg-sign]
  IFTRUE:
    ASGN: gpg-sign = yes
  END COND
  COND: HEADER[Subject] :posix [rot13-all]
  IFTRUE:
    ASGN: guile-process = rot-13 #:body
    ASGN: guile-process = rot-13 #:subject
  END COND
  COND: HEADER[Subject] :posix [rot13-body]
  IFTRUE:
    ASGN: guile-process = rot-13 #:body
  END COND
  COND: HEADER[Subject] :posix [rot13-subject]
  IFTRUE:
    ASGN: guile-process = rot-13 #:subject
  END COND
  COND: HEADER[Subject] :posix [body-append]
  IFTRUE:
    ASGN: body-append = misc/notes.txt
  END COND
  COND: HEADER[Subject] :posix [ALL]
  IFTRUE:
    ASGN: body-append = misc/notes.txt
    ASGN: gpg-encrypt = USERNAME
    ASGN: guile-process = rot-13 #:body
    ASGN: guile-process = rot-13 #:subject
  END COND
END SECTION RULE
:END PATTERN
:END TEST
