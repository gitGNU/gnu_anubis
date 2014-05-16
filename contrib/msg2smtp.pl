# Apart from the three lines below, it is actually a -*- perl -*- code.
eval '(exit $?0)' && eval 'exec perl -wS "$0" ${1+"$@"}'
  & eval 'exec perl -wS "$0" $argv:q'
    if 0;

my $usage = qq!
$0 takes a mail message on STDIN and relays it to an SMTP server.

$0 -h HOST [options]
  -h HOST        (hostname of SMTP server, often 'localhost')

  Options:

  -p PORT        (port of the SMTP server)
  -e HELO_DOMAIN (domain we use when to say helo to smtp server)
  -U USERNAME    (ESMTP auth username)
  -P PASSWORD    (ESMTP auth password)
  -m MECHANISM   (ESMTP auth mechanism - default is PLAIN)
  -d             (shows SMTP conversation and perl debugging)
    !;

#------------------------------------------
# INDEX

# 0. GPL License
# 1. Module Dependencies
# 2. Set options by Command-line Arguments
# 3. Read Message by STDIN
# 4. Extend Net::SMTP to allow us to choose an auth mechanism
# 5. Send message via SMTP

#------------------------------------------
# 0. GPL License
#
#  This file is part of GNU Anubis.
#  Copyright (C) 2001-2014 The Anubis Team.
# 
#  GNU Anubis is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
# 
#  GNU Anubis is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with GNU Anubis; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
# 
#  msg2smtp.pl code: Michael de Beer <michael@debeer.org>
#    ext_auth() mainly taken from the Net::SMTP module
#
#  http://www.gnu.org/software/anubis/
#
#------------------------------------------
# 1. Module Dependencies

use warnings;  use strict;
use Getopt::Std;
use vars qw!$opt_h $opt_p $opt_e $opt_U $opt_P $opt_d $opt_m!;

# REQUIRED MODULES:
use Mail::Address;
use Net::SMTP;
# perl -MCPAN -e 'install Mail::Address'
# perl -MCPAN -e 'install Net::SMTP'

# OPTIONAL MODULES: Authen:SASL (for ESMTP auth)
# perl -MCPAN -e 'install Authen::SASL'

# Note: this script originally used functions from Mail::Box to:
# * parse messages and
# * interface with Net::SMTP
# However, I discovered Mail::Box did not support these options:
#   'port username password'
# So, I am not using Mail::Box.
# # use Mail::Box; use Mail::Transport::SMTP;

#------------------------------------------
# 2. Set options by Command-line Arguments

getopts('dh:p:e:U:P:m:');

my (%smtp_options, $host, $username, $password, $auth_mech);

if ($opt_h) { 
    $host = $opt_h;
} else {
    print $usage, "\n";
    exit(255);
} 

$smtp_options{Port} = $opt_p if ($opt_p);
$smtp_options{Hello} = $opt_e if ($opt_e);
$smtp_options{Debug} = 1 if ($opt_d);
$username = $opt_U if ($opt_U);
$password = $opt_P if ($opt_P);
$auth_mech = $opt_m ? $opt_m : 'PLAIN'; # not tested other AUTH mechanisms

#------------------------------------------
# 3. Read Message by STDIN

# read the message and parse the headers for RCPT and FROM
my ($from, @rcpt);
my ($txt_head) = '';
my ($txt_body) = '';

# the only trick thing are To: lines that are folded
# I deal with that with 4 Rules, below.

my ($tmp, $readyflag, $chunk, @to_addresses);
$readyflag = 0;

HEAD: while ($tmp = <STDIN>) {

# Rule 1: If the line is a blank line, exit HEAD section
  if ($tmp =~ /^$/) {
      if ($readyflag eq 1) {
          last;
      }
      else {
          next HEAD;
      }
  }

# Rule 2: If it is a folded line, add line to $chunk, skip to next line
  if ($tmp =~ /^\s+\S+/) { $chunk .= $tmp; next HEAD  };

# Rule 3: If it is not a folded line, process old chunk
  $_ = $chunk ? $chunk : '';
  if (/^From:/i) {
      s/^From://i;
      my @from_addresses;
      @from_addresses = Mail::Address->parse($_);
      $from = pop(@from_addresses)->address;
      die "From: address invalid" unless $from;
      die "there is more than one From: address" if @from_addresses;
      $readyflag = 1;
  } elsif (/^(To|CC|BCC):/i) {
      s/^(To|CC|BCC)://i;
      @to_addresses = (); # re-initialize because we re-enter this loop
      @to_addresses = Mail::Address->parse($_);
      foreach my $obj (@to_addresses) {
	  push @rcpt, $obj->address;
      }
  }
  $txt_head .= $chunk if ($chunk);

# Rule 4: start a new chunk
  $chunk = $tmp;
}

while (<STDIN>) {
   $txt_body .= $_;
}

#if ($smtp_options{Debug}) {
#    print "\n---BEGINNING OF DEBUG---\n";
#    print "From: $from\n"; map {print "To: $_\n"} @rcpt;
#    print "MsgBody:\n$txt_body\n";
#    print "---END OF DEBUG---\n";
#}

#------------------------------------------
# 4. Extend Net::SMTP to allow us to choose and auth mechanism

# We make an extend-auth method, as Net::SMTP::auth() 
# does not seem to accurately pick a mechanism

package Net::SMTP;
sub ext_auth { # taken from Net::SMTP, only modify $mechanisms
    my ($self, $username, $password, $mechanisms) = @_;

    require MIME::Base64;
    require Authen::SASL;

    my $m = $self->supports('AUTH',500,["Command unknown: 'AUTH'"]);
    return unless defined $m;
    my $sasl;

    if (ref($username) and UNIVERSAL::isa($username,'Authen::SASL')) {
      $sasl = $username;
      $sasl->mechanism($mechanisms);
    }
    else {
      die "auth(username, password)" if not length $username;
      $sasl = Authen::SASL->new(mechanism=> $mechanisms,
				callback => { user => $username,
                                              pass => $password,
					      authname => $username,
                                            });
    }
    my $client = $sasl->client_new('smtp',${*$self}{'net_smtp_host'},0);
    my $str    = $client->client_start;

    # We dont support sasl mechanisms that encrypt the socket traffic.
    # todo that we would really need to change the ISA hierarchy
    # so we dont inherit from IO::Socket, but instead hold it in an attribute

    my @cmd = ("AUTH", $client->mechanism, MIME::Base64::encode_base64($str,''));
    my $code;

    while (($code = $self->command(@cmd)->response()) == CMD_MORE) {
      @cmd = (MIME::Base64::encode_base64(
	$client->client_step(
	  MIME::Base64::decode_base64(
	    ($self->message)[0]
	  )
	), ''
      ));
    }

    $code == CMD_OK;
}

#------------------------------------------
# 5. Send message via SMTP

package main;

my $smtp = Net::SMTP->new($host, %smtp_options);
$smtp or die "failed to connect to SMTP server";

if ($username) { 
  print "WARNING: failed ESMTP auth using username '$username'...trying to send anyway\n" unless $smtp->ext_auth ($username, $password, $auth_mech);
};
$smtp->mail($from) or die "server rejected FROM address '$from'";
$smtp->to(@rcpt, {SkipBad => 1}) or die "server rejected all TO addresses";
$smtp->data() or die "server crashed while preparing to send DATA";
$smtp->datasend($txt_head) or die "server crashed while sending DATA.1";
$smtp->datasend("\n") or die "server crashed while sending DATA.2";
$smtp->datasend($txt_body) or die "server crashed while sending DATA.3";
$smtp->dataend() or die "server crashed while ending DATA";
$smtp->quit or die "server crashed while quiting - message may not be lost";;

__END__

# EOF

