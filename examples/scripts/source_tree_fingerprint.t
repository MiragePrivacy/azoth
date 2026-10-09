#!/usr/bin/env perl

use strict;
use warnings;
no warnings 'once';

use File::Path qw(make_path);
use File::Temp qw(tempdir);
use FindBin qw($Bin);
use Test::More;

my $loaded = do "$Bin/source_tree_fingerprint.pl";
die $@ if !$loaded && $@;
die $! if !$loaded && $!;

sub write_bytes {
    my ($path, $bytes) = @_;
    open my $output, '>:raw', $path or die "cannot write $path: $!";
    print {$output} $bytes;
    close $output or die "cannot close $path: $!";
}

sub run_git {
    my ($repo, @arguments) = @_;
    return Azoth::SourceTreeFingerprint::_run_git($repo, @arguments);
}

my @golden_records = (
    [ $Azoth::SourceTreeFingerprint::SYMLINK,      'z-link', '../target' ],
    [ $Azoth::SourceTreeFingerprint::REGULAR_FILE, 'a.txt',  "alpha\n" ],
);
my $golden = '2e1f99a3178df656d29ef2a7be9090f1e251d05962d900b4ca8eef68f8c6d1d2';
is(
    Azoth::SourceTreeFingerprint::fingerprint_records(@golden_records),
    $golden,
    'record encoding matches its fixed SHA-256 vector'
);
is(
    Azoth::SourceTreeFingerprint::fingerprint_records(reverse @golden_records),
    $golden,
    'caller record order does not affect the digest'
);

open my $benchmark, '<:raw', "$Bin/../src/bin/foundation_benchmark.rs"
  or die "cannot read benchmark source: $!";
local $/;
my $benchmark_source = <$benchmark>;
close $benchmark;
like(
    $benchmark_source,
    qr/\Q$Azoth::SourceTreeFingerprint::ALGORITHM_DESCRIPTION\E/,
    'helper and benchmark publish the same algorithm description'
);

my $temporary = tempdir(CLEANUP => 1);
my $origin = "$temporary/fixture-origin";
my $root = "$temporary/root";
make_path($origin, $root);

run_git($origin, 'init', '-q');
write_bytes("$origin/.gitignore", "ignored-child\n");
write_bytes("$origin/fixture.bin", 'fixture-v1');
run_git($origin, 'add', '.gitignore', 'fixture.bin');
run_git(
    $origin, '-c', 'user.name=Azoth Test', '-c',
    'user.email=azoth@example.invalid', 'commit', '-q', '-m', 'fixture'
);

run_git($root, 'init', '-q');
write_bytes("$root/.gitignore", "ignored-root\n");
write_bytes("$root/tracked.txt", 'tracked');
write_bytes("$root/untracked.txt", 'untracked');
write_bytes("$root/ignored-root", 'ignored');
symlink 'tracked.txt', "$root/tracked-link" or die "cannot create symlink: $!";
run_git($root, 'add', '.gitignore', 'tracked.txt');
run_git(
    $root, '-c', 'protocol.file.allow=always', 'submodule', 'add', '-q',
    $origin, 'deps/fixture'
);
my $submodule = "$root/deps/fixture";
write_bytes("$submodule/local.bin", 'local-v1');
write_bytes("$submodule/ignored-child", 'ignored');

my @leaves = Azoth::SourceTreeFingerprint::collect_leaves($root);
my %paths = map { $_->{path} => 1 } @leaves;
ok($paths{'.gitmodules'}, 'root tracked files are included');
ok($paths{'tracked-link'}, 'untracked symlinks are included');
ok($paths{'untracked.txt'}, 'root untracked files are included');
ok($paths{'deps/fixture/fixture.bin'}, 'submodule tracked files are included');
ok($paths{'deps/fixture/local.bin'}, 'submodule untracked files are included');
ok(!$paths{'ignored-root'}, 'root ignored files are excluded');
ok(!$paths{'deps/fixture/ignored-child'}, 'submodule ignored files are excluded');

my ($first, $first_count) =
  Azoth::SourceTreeFingerprint::repository_fingerprint($root);
my ($replay, $replay_count) =
  Azoth::SourceTreeFingerprint::repository_fingerprint($root);
is($replay, $first, 'repository digest is deterministic');
is($replay_count, $first_count, 'repository leaf count is deterministic');

write_bytes("$root/ignored-root", 'changed but ignored');
my ($ignored_change) =
  Azoth::SourceTreeFingerprint::repository_fingerprint($root);
is($ignored_change, $first, 'ignored content does not affect the digest');

write_bytes("$submodule/local.bin", 'local-v2');
my ($submodule_change) =
  Azoth::SourceTreeFingerprint::repository_fingerprint($root);
isnt($submodule_change, $first, 'dirty submodule content affects the digest');

run_git($root, 'submodule', 'deinit', '-f', '--', 'deps/fixture');
my $uninitialized_ok = eval {
    Azoth::SourceTreeFingerprint::repository_fingerprint($root);
    1;
};
ok(!$uninitialized_ok, 'uninitialized tracked submodules are rejected');
like($@, qr/not initialized/, 'uninitialized-submodule error is explicit');

done_testing();
