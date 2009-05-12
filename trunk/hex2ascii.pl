#!/usr/bin/perl -w
#
# Quick and nasty script to parse hex results that come
# back from ssl-enum verbose output.
#
# This file is part of the ssl-enum package.
#

use strict;

while (<>) {
	my $line=$_;
	my $string = pack 'H*', $line;
	print $string, "\n";
}
