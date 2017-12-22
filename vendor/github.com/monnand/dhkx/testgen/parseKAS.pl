my $p = "";
my $g = "";
my $xa = "";
my $xb = "";
my $ya = "";
my $yb = "";
my $zz = "";
my $pass = "";
my $count = 0;
my $id = 0;
while (<>) {
	chomp;
	if (/P = ([0-9a-f]+)/) {
		$p = $1;
	} elsif (/G = ([0-9a-f]+)/) {
		$g = $1;
	} elsif (/XstatCAVS = ([0-9a-f]+)/) {
		$xa = $1;
	} elsif (/YstatCAVS = ([0-9a-f]+)/) {
		$ya = $1;
	} elsif (/XstatIUT = ([0-9a-f]+)/) {
		$xb = $1;
	} elsif (/YstatIUT = ([0-9a-f]+)/) {
		$yb = $1;
	} elsif (/^Z = ([0-9a-f]+)/) {
		$zz = $1;
	} elsif (/Result = ([PF]).+/) {
		if ($1 eq "F") {
			$pass = 0;
		} elsif ($1 eq "P") {
			$pass = 1;
		}
	} elsif (/COUNT = ([0-9]+)/) {
		$id = $1;
		if ($pass and $p and $g and $xa and $xb and $ya and $yb and $zz) {
			print "// Test case $count\n";
			print "func TestNIST_$count(tt *testing.T) {\n";
			print "var t *dhTestCase\n";
			print "var err error\n";
			print "t = new(dhTestCase)\n";
			print "t.p, _ = new(big.Int).SetString(\"$p\", 16)\n";
			print "t.g, _ = new(big.Int).SetString(\"$g\", 16)\n";
			print "t.xa, _ = new(big.Int).SetString(\"$xa\", 16)\n";
			print "t.xb, _ = new(big.Int).SetString(\"$xb\", 16)\n";
			print "t.ya, _ = new(big.Int).SetString(\"$ya\", 16)\n";
			print "t.yb, _ = new(big.Int).SetString(\"$yb\", 16)\n";
			print "t.zz, _ = new(big.Int).SetString(\"$zz\", 16)\n";
			print "err = t.test()\n";
			print "if err != nil {\n";
			print "tt.Errorf(\"Test Case $count failed: %v\", err)\n";
			print "}\n";
			print "}\n";
			print "\n";
			$count++;
		}
	}
}
