#!/usr/local/bin/perl -w
# $Id: md5-bench.pl,v 1.2 2000/09/17 13:43:32 lackas Exp $
# Benchmark
# compares Digest::Perl::MD5 and Digest::MD5

use strict;
use Benchmark;
use Digest::MD5;
use Digest::Perl::MD5;

timethese(100_000,{
	'MD5' => 'Digest::MD5::md5(q!delta!)',
	'Perl::MD5' => 'Digest::Perl::MD5::md5(q!delta!)',
});
