#!/usr/local/bin/perl -w
#$Id$

package Digest::Perl::MD5;
use strict;
use vars qw($VERSION @ISA @EXPORTER @EXPORT_OK);

@EXPORT_OK = qw(md5 md5_hex md5_base64);

@ISA = 'Exporter';
$VERSION = '0.2';

# I-Vektor
use constant A => 0x67_45_23_01;
use constant B => 0xef_cd_ab_89;
use constant C => 0x98_ba_dc_fe;
use constant D => 0x10_32_54_76;

# for internal use
use constant MAX => 0xFFFFFFFF;
use constant NULL => "\0";

# Shift-lengths
use constant S11 => 7;
use constant S12 => 12;
use constant S13 => 17;
use constant S14 => 22;
use constant S21 => 5;
use constant S22 => 9;
use constant S23 => 14;
use constant S24 => 20;
use constant S31 => 4;
use constant S32 => 11;
use constant S33 => 16;
use constant S34 => 23;
use constant S41 => 6;
use constant S42 => 10;
use constant S43 => 15;
use constant S44 => 21;

# for debugging
sub hexdump($) {
	my $t = shift;
	for (split //,$t) {
      printf '%02x ', ord;
    }
    print "\n";
}

# padd a message to a multiple of 64
sub padding($) {
    my $msg = shift;
    my $length = length($msg) * 8;
    $msg .= chr(128); # ein bit ganz links
    while( length($msg) % 64 != 56 ) { $msg .= NULL }
    $msg .= pack 'LL', $length & MAX , $length & 0x00000000;
    return $msg;
}

#sub F($$$) {
#	my ($X, $Y, $Z) = map {pack 'L', $_} @_;
#	unpack 'L', ($X & $Y) | ((~$X) & $Z)
#}
#sub G($$$) {
#	my ($X, $Y, $Z) = map {pack 'L', $_} @_;
#	unpack 'L', (($X & $Z) | ($Y & (~$Z)))
#}
#sub H($$$) {
#	my ($X, $Y, $Z) = map {pack 'L', $_} @_;
#	unpack 'L', ($X ^ $Y ^ $Z) 
#}
#sub I($$$) {
#	my ($X, $Y, $Z) = map {pack 'L', $_} @_;
#	unpack 'L', $Y ^ ($X | (~$Z))
#}

#    ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
sub rotate_left($$) {
	($_[0] << $_[1]) | ($_[0] >> (32-$_[1]))
}


sub FF(\$$$$$$$) {
  my $X = pack'L',$_[1];
  ${$_[0]} = sum(rotate_left(sum(${$_[0]},
             sum(unpack('L',(($X & pack('L',$_[2])) | ((~$X) & pack('L',$_[3])))),$_[4],$_[6])),$_[5]),$_[1]);
}

sub GG(\$$$$$$$) {
  my $Z = pack'L', $_[3];
  ${$_[0]} = sum(rotate_left(sum(${$_[0]},
             sum(unpack('L',(pack('L',$_[1]) & $Z) | ( pack('L',$_[2]) & (~$Z))),$_[4],$_[6])),$_[5]),$_[1]);
}

sub HH(\$$$$$$$) {
  ${$_[0]} = sum(rotate_left(sum(${$_[0]},
             sum(unpack('L',(pack('L',$_[1]) ^ pack('L',$_[2]) ^ pack('L',$_[3]))),$_[4],$_[6])),$_[5]),$_[1]);
}

sub II(\$$$$$$$) {
  ${$_[0]} = sum(rotate_left(sum(${$_[0]},
             sum(unpack('L',pack('L',$_[2]) ^ (pack('L',$_[1]) | (~pack('L',$_[3])))),$_[4],$_[6])),$_[5]),$_[1]);
}


# hack
sub sum(@) {
  my $res;
  for (@_) { # cut to 32bit
        $res += $_;        
  }
  while ($res > MAX) {$res -= MAX+1}
  $res;
}

#sub FF(\$$$$$$$) {
#  my ($a,$b,$c,$d,$x,$s,$ac) = @_;
#  $$a = sum($$a,sum(F($b,$c,$d),$x,$ac));
#  $$a = rotate_left($$a,$s);
#  $$a = sum($$a,$b);
#}

#sub GG(\$$$$$$$) {
#  my ($a,$b,$c,$d,$x,$s,$ac) = @_;
#  $$a = sum($$a, sum(G($b,$c,$d),$x,$ac)); 
#  $$a = rotate_left($$a, $s);
#  $$a = sum($$a,$b); 
#}

#sub HH(\$$$$$$$) {
#  my ($a,$b,$c,$d,$x,$s,$ac) = @_;
#  $$a = sum($$a, sum(H($b,$c,$d),$x,$ac)); 
#  $$a = rotate_left($$a, $s);
#  $$a = sum($$a,$b); 
#}

#sub II(\$$$$$$$) {
#  my ($a,$b,$c,$d,$x,$s,$ac) = @_;
#  $$a = sum($$a, sum(I($b,$c,$d),$x,$ac)); 
#  $$a = rotate_left($$a, $s);
#  $$a = sum($$a,$b); 
#}

sub round($$$$@) {
  my @state;
  (@state[0..3],my @x) = @_;
  my ($a,$b,$c,$d) = @state;
  my $X;
#  FF($a, $b, $c, $d, $x[ 0], S11, 0xd76aa478); #/* 1 */
  $X = pack'L',$b;
  $a = sum(rotate_left(sum($a,
       sum(unpack('L',(($X & pack('L',$c)) | ((~$X) & pack('L',$d)))),$x[0],0xd76aa478)),S11),$b);
#  FF($d, $a, $b, $c, $x[ 1], S12, 0xe8c7b756); #/* 2 */
  my $X = pack'L',$a;
  $d = sum(rotate_left(sum($d,
       sum(unpack('L',(($X & pack('L',$b)) | ((~$X) & pack('L',$c)))),$x[1],0xe8c7b756)),S12),$a);
#  FF($c, $d, $a, $b, $x[ 2], S13, 0x242070db); #/* 3 */
  my $X = pack'L',$d;
  $c = sum(rotate_left(sum($c,
       sum(unpack('L',(($X & pack('L',$a)) | ((~$X) & pack('L',$b)))),$x[2],0x242070db)),S13),$d);
#  FF($b, $c, $d, $a, $x[ 3], S14, 0xc1bdceee); #/* 4 */
  my $X = pack'L',$c;
  $b = sum(rotate_left(sum($b,
      sum(unpack('L',(($X & pack('L',$d)) | ((~$X) & pack('L',$a)))),$x[3],0xc1bdceee)),S14),$c);
#  FF($a, $b, $c, $d, $x[ 4], S11, 0xf57c0faf); #/* 5 */
  my $X = pack'L',$b;
  $a = sum(rotate_left(sum($a,
       sum(unpack('L',(($X & pack('L',$c)) | ((~$X) & pack('L',$d)))),$x[4],0xf57c0faf)),S11),$b);
#  FF($d, $a, $b, $c, $x[ 5], S12, 0x4787c62a); #/* 6 */
  my $X = pack'L',$a;
  $d = sum(rotate_left(sum($d,
       sum(unpack('L',(($X & pack('L',$b)) | ((~$X) & pack('L',$c)))),$x[5],0x4787c62a)),S12),$a);
#  FF($c, $d, $a, $b, $x[ 6], S13, 0xa8304613); #/* 7 */
  my $X = pack'L',$d;
  $c = sum(rotate_left(sum($c,
       sum(unpack('L',(($X & pack('L',$a)) | ((~$X) & pack('L',$b)))),$x[6],0xa8304613)),S13),$d);
#  FF($b, $c, $d, $a, $x[ 7], S14, 0xfd469501); #/* 8 */
  my $X = pack'L',$c;
  $b = sum(rotate_left(sum($b,
       sum(unpack('L',(($X & pack('L',$d)) | ((~$X) & pack('L',$a)))),$x[7],0xfd469501)),S14),$c);
#  FF($a, $b, $c, $d, $x[ 8], S11, 0x698098d8); #/* 9 */
  my $X = pack'L',$b;
  $a = sum(rotate_left(sum($a,
       sum(unpack('L',(($X & pack('L',$c)) | ((~$X) & pack('L',$d)))),$x[8],0x698098d8)),S11),$b);

#  my $X = pack'L',$_[1];
#  ${$_[0]} = sum(rotate_left(sum(${$_[0]},
#             sum(unpack('L',(($X & pack('L',$_[2])) | ((~$X) & pack('L',$_[3])))),$_[4],$_[6])),$_[5]),$_[1]);


#  FF($d, $a, $b, $c, $x[ 9], S12, 0x8b44f7af); #/* 10 */
  my $X = pack'L',$a;
  $d = sum(rotate_left(sum($d,
       sum(unpack('L',(($X & pack('L',$b)) | ((~$X) & pack('L',$c)))),$x[9],0x8b44f7af)),S12),$a);
       
  FF($c, $d, $a, $b, $x[10], S13, 0xffff5bb1); #/* 11 */
  FF($b, $c, $d, $a, $x[11], S14, 0x895cd7be); #/* 12 */
  FF($a, $b, $c, $d, $x[12], S11, 0x6b901122); #/* 13 */
  FF($d, $a, $b, $c, $x[13], S12, 0xfd987193); #/* 14 */
  FF($c, $d, $a, $b, $x[14], S13, 0xa679438e); #/* 15 */
  FF($b, $c, $d, $a, $x[15], S14, 0x49b40821); #/* 16 */
  
  GG ($a, $b, $c, $d, $x[ 1], S21, 0xf61e2562); #/* 17 */
  GG ($d, $a, $b, $c, $x[ 6], S22, 0xc040b340); #/* 18 */
  GG ($c, $d, $a, $b, $x[11], S23, 0x265e5a51); #/* 19 */
  GG ($b, $c, $d, $a, $x[ 0], S24, 0xe9b6c7aa); #/* 20 */
  GG ($a, $b, $c, $d, $x[ 5], S21, 0xd62f105d); #/* 21 */
  GG ($d, $a, $b, $c, $x[10], S22,  0x2441453); #/* 22 */
  GG ($c, $d, $a, $b, $x[15], S23, 0xd8a1e681); #/* 23 */
  GG ($b, $c, $d, $a, $x[ 4], S24, 0xe7d3fbc8); #/* 24 */
  GG ($a, $b, $c, $d, $x[ 9], S21, 0x21e1cde6); #/* 25 */
  GG ($d, $a, $b, $c, $x[14], S22, 0xc33707d6); #/* 26 */
  GG ($c, $d, $a, $b, $x[ 3], S23, 0xf4d50d87); #/* 27 */
  GG ($b, $c, $d, $a, $x[ 8], S24, 0x455a14ed); #/* 28 */
  GG ($a, $b, $c, $d, $x[13], S21, 0xa9e3e905); #/* 29 */
  GG ($d, $a, $b, $c, $x[ 2], S22, 0xfcefa3f8); #/* 30 */
  GG ($c, $d, $a, $b, $x[ 7], S23, 0x676f02d9); #/* 31 */
  GG ($b, $c, $d, $a, $x[12], S24, 0x8d2a4c8a); #/* 32 */

  HH ($a, $b, $c, $d, $x[ 5], S31, 0xfffa3942); #/* 33 */
  HH ($d, $a, $b, $c, $x[ 8], S32, 0x8771f681); #/* 34 */
  HH ($c, $d, $a, $b, $x[11], S33, 0x6d9d6122); #/* 35 */
  HH ($b, $c, $d, $a, $x[14], S34, 0xfde5380c); #/* 36 */
  HH ($a, $b, $c, $d, $x[ 1], S31, 0xa4beea44); #/* 37 */
  HH ($d, $a, $b, $c, $x[ 4], S32, 0x4bdecfa9); #/* 38 */
  HH ($c, $d, $a, $b, $x[ 7], S33, 0xf6bb4b60); #/* 39 */
  HH ($b, $c, $d, $a, $x[10], S34, 0xbebfbc70); #/* 40 */
  HH ($a, $b, $c, $d, $x[13], S31, 0x289b7ec6); #/* 41 */
  HH ($d, $a, $b, $c, $x[ 0], S32, 0xeaa127fa); #/* 42 */
  HH ($c, $d, $a, $b, $x[ 3], S33, 0xd4ef3085); #/* 43 */
  HH ($b, $c, $d, $a, $x[ 6], S34,  0x4881d05); #/* 44 */
  HH ($a, $b, $c, $d, $x[ 9], S31, 0xd9d4d039); #/* 45 */
  HH ($d, $a, $b, $c, $x[12], S32, 0xe6db99e5); #/* 46 */
  HH ($c, $d, $a, $b, $x[15], S33, 0x1fa27cf8); #/* 47 */
  HH ($b, $c, $d, $a, $x[ 2], S34, 0xc4ac5665); #/* 48 */

  II ($a, $b, $c, $d, $x[ 0], S41, 0xf4292244); #/* 49 */
  II ($d, $a, $b, $c, $x[ 7], S42, 0x432aff97); #/* 50 */
  II ($c, $d, $a, $b, $x[14], S43, 0xab9423a7); #/* 51 */
  II ($b, $c, $d, $a, $x[ 5], S44, 0xfc93a039); #/* 52 */
  II ($a, $b, $c, $d, $x[12], S41, 0x655b59c3); #/* 53 */
  II ($d, $a, $b, $c, $x[ 3], S42, 0x8f0ccc92); #/* 54 */
  II ($c, $d, $a, $b, $x[10], S43, 0xffeff47d); #/* 55 */
  II ($b, $c, $d, $a, $x[ 1], S44, 0x85845dd1); #/* 56 */
  II ($a, $b, $c, $d, $x[ 8], S41, 0x6fa87e4f); #/* 57 */
  II ($d, $a, $b, $c, $x[15], S42, 0xfe2ce6e0); #/* 58 */
  II ($c, $d, $a, $b, $x[ 6], S43, 0xa3014314); #/* 59 */
  II ($b, $c, $d, $a, $x[13], S44, 0x4e0811a1); #/* 60 */
  II ($a, $b, $c, $d, $x[ 4], S41, 0xf7537e82); #/* 61 */
  II ($d, $a, $b, $c, $x[11], S42, 0xbd3af235); #/* 62 */
  II ($c, $d, $a, $b, $x[ 2], S43, 0x2ad7d2bb); #/* 63 */
  II ($b, $c, $d, $a, $x[ 9], S44, 0xeb86d391); #/* 64 */
  
  return (sum($state[0],$a),sum($state[1],$b),sum($state[2],$c),sum($state[3],$d));
}


# object part of this module
sub new {
	my $class = shift;
    bless {}, $class;
}

sub reset {
	my $self = shift;
    delete $self->{data}
}

sub add(@) {
	my $self = shift;
    $self->{data} .= join'', @_;
    $self
}

sub addfile {
  	my $self = shift;
    my $fh = shift;
    $self->{data} .= do{local$/;<$fh>};
    $self
}

sub digest {
	my $self = shift;
    md5($self->{data})
}

sub hexdigest {
	my $self = shift;
    md5_hex($self->{data})
}

sub b64digest {
	my $self = shift;
    md5_base64($self->{data})
}

# Liefert Chunks mit je $size bytes.
sub chunk($$) {
  my ($t,$size) = @_;
  my @res;
  my $l = length ($t) / $size;
  for (my $i = 0; $i < $l; $i++) {
	 	push @res, substr($t,$i*$size,$size);
  }
  @res;
}

sub md5($) {
    my $message = shift;
	my $message_padded = padding($message);
	my @blocks = chunk($message_padded,64);
	my ($a,$b,$c,$d) = (A,B,C,D);
	foreach my $X (@blocks) {
		my @X = map { unpack 'L', $_ } chunk($X,4);	
		($a,$b,$c,$d) = round($a,$b,$c,$d,@X);
	}
	my $res = pack 'L4',$a,$b,$c,$d;    
    return $res;
}

sub md5_hex($) {  
  my $data = shift;
  unpack 'H*', md5($data);
}

sub md5_base64($) {
  my $data = shift;
  encode_base64(md5($data));
}


sub encode_base64 ($;$) {
    my $res;
    my $eol = $_[1];
    $eol = "\n" unless defined $eol;
    pos($_[0]) = 0;                          # ensure start at the beginning
    while ($_[0] =~ /(.{1,45})/gs) {
	$res .= substr(pack('u', $1), 1);
	chop($res);
    }
    $res =~ tr|` -_|AA-Za-z0-9+/|;               # `# help emacs
    chop($res);chop($res);
    $res;
}
