use Test;
use strict;
use lib './lib';

BEGIN {plan tests => 5}

use Digest::Perl::MD5 qw(md5 md5_hex md5_base64);



# 1 Testsuite
print "Trying md5_hex on test suite...\n";
ok( md5_hex('') eq 'd41d8cd98f00b204e9800998ecf8427e' and
    md5_hex('a') eq '0cc175b9c0f1b6a831c399e269772661' and
    md5_hex('abc') eq '900150983cd24fb0d6963f7d28e17f72' and
    md5_hex('message digest') eq 'f96b697d7cb7938d525a2f31aaf161d0' and
    md5_hex('abcdefghijklmnopqrstuvwxyz') eq
    	'c3fcd3d76192e4007dfb496cca67e13b' and
    md5_hex('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') eq
    	'd174ab98d277d9f5a5611c2c9f419d9f' and
    md5_hex('12345678901234567890123456789012345678901234567890123456789012345678901234567890') eq
    	'57edf4a22be3c955ac49da2e2107b67a'
);

# 2 md5_base64
print "Trying md5_base64...\n";
ok ( md5_base64('delta') eq 'Y7yr+GqamRhkd3xjHFt2Fw' );

# 3 Object
print "Testing MD5-Object...\n";
my $c = new Digest::Perl::MD5;
$c->add('XdeltaX');
ok( $c->b64digest eq 'hLA/iI1q1iIKz+uffnsN6w');
$c->reset;

open FILE, './lib/Digest/Perl/MD5.pm' or die $!;
print $c->addfile(*FILE)->hexdigest,"\n"; # DEBUG
# 4 Object 2
ok ( $c->addfile(*FILE)->hexdigest eq '24e998f1464ac1a26f037e292b0a9b0a');

# 5 Speed-Test
print "Speed-Test (be patient)...\n";
my $count = 2000;
my $t1 = time;
for (1..$count) { md5('delta') } # encode 64Byte blocks
my $t2 = time;
printf "%d blocks took %ds => %.2f blocks/second\n",
       $count, $t2-$t1, $count/($t2-$t1);
