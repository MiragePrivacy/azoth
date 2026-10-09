#!/usr/bin/env perl

# Compute Azoth's canonical dirty-worktree source fingerprint.
#
# This helper uses only modules shipped with Perl. It fingerprints tracked files
# and non-ignored untracked files in the root worktree and all initialized tracked
# submodules, including the escrow fixture submodule.
#
# Official-run example, from the Azoth repository root:
#
#   azoth_tree_hash="$(perl examples/scripts/source_tree_fingerprint.pl --repo .)"
#   azoth_base_revision="$(git rev-parse HEAD)"
#   cargo run --locked --release -p azoth-examples --bin foundation_benchmark -- \
#     --source-revision "base:${azoth_base_revision};tree-sha256:${azoth_tree_hash}" ...
#
# Only the lowercase digest is written to stdout. Errors go to stderr and return
# a non-zero exit status.

package Azoth::SourceTreeFingerprint;

use strict;
use warnings;

use Cwd qw(abs_path);
use Digest::SHA ();
use File::Spec ();
use Getopt::Long qw(GetOptionsFromArray);
use IO::Select ();
use IPC::Open3 qw(open3);
use Symbol qw(gensym);

our $ALGORITHM_DESCRIPTION = 'azoth-source-tree-sha256-v1: in the root Git worktree and recursively in every initialized tracked submodule, enumerate `git ls-files --cached --others --exclude-standard -z`; replace each gitlink with the recursively enumerated leaf entries beneath its root-relative path and reject uninitialized gitlinks, missing leaves, or leaf types other than regular files and symlinks; represent a regular-file leaf as kind byte 0x00 plus its current file bytes and a symlink leaf as kind byte 0x01 plus its raw link-target bytes; sort leaves lexicographically by raw root-relative path bytes; SHA-256 the ASCII domain `AZOTH_SOURCE_TREE_SHA256_V1` followed by a NUL byte and, for each leaf, its kind byte, u64-be(path byte length), path bytes, u64-be(payload byte length), and payload bytes; encode the digest as lowercase hex';
our $DOMAIN           = "AZOTH_SOURCE_TREE_SHA256_V1\0";
our $REGULAR_FILE     = 0;
our $SYMLINK          = 1;
our $GITLINK_MODE     = '160000';

sub _display {
    my ($raw) = @_;
    $raw =~ s/([^\x20-\x7e]|\\)/sprintf('\\x%02x', ord($1))/ge;
    return $raw;
}

sub _run_git {
    my ($repo, @arguments) = @_;
    my $stderr = gensym();
    my ($stdin, $stdout);
    my $pid = eval { open3($stdin, $stdout, $stderr, 'git', '-C', $repo, @arguments) };
    die "cannot start git in " . _display($repo) . ": $@" if !defined $pid;
    close $stdin;
    binmode $stdout;
    binmode $stderr;

    my $stdout_fileno = fileno($stdout);
    my $stderr_fileno = fileno($stderr);
    my $selector = IO::Select->new($stdout, $stderr);
    my ($output, $error) = ('', '');
    while (my @ready = $selector->can_read()) {
        for my $handle (@ready) {
            my $buffer = '';
            my $read = sysread($handle, $buffer, 65_536);
            die "cannot read git output: $!\n" if !defined $read;
            if ($read == 0) {
                $selector->remove($handle);
                close $handle;
                next;
            }
            if (fileno($handle) == $stdout_fileno) {
                $output .= $buffer;
            }
            elsif (fileno($handle) == $stderr_fileno) {
                $error .= $buffer;
            }
        }
    }
    waitpid($pid, 0);
    my $status = $?;
    if ($status != 0) {
        $error =~ s/\s+\z//;
        my $exit_code = $status == -1 ? -1 : $status >> 8;
        die 'git failed in '
          . _display($repo)
          . " (exit $exit_code): $error\n";
    }
    return $output;
}

sub _nul_records {
    my ($raw, $label) = @_;
    return () if $raw eq '';
    die "$label did not produce a NUL-terminated record stream\n"
      if substr($raw, -1) ne "\0";
    chop $raw;
    return split /\0/, $raw, -1;
}

sub _index_modes {
    my ($repo) = @_;
    my %modes;
    for my $record (_nul_records(_run_git($repo, 'ls-files', '--stage', '-z'),
            'git ls-files --stage'))
    {
        my ($mode, $object_id, $stage, $path) =
          $record =~ /\A([0-7]+) ([0-9a-f]+) ([0-3])\t(.*)\z/s;
        die "malformed git index record\n" if !defined $path;
        die 'unmerged index entry is unsupported: '
          . _display($path)
          . " (stage $stage)\n"
          if $stage ne '0';
        die 'duplicate git index entry: ' . _display($path) . "\n"
          if exists $modes{$path};
        $modes{$path} = $mode;
    }
    return \%modes;
}

sub _listed_paths {
    my ($repo) = @_;
    my @paths = _nul_records(
        _run_git(
            $repo, '-c', 'core.quotepath=false', 'ls-files', '--cached',
            '--others', '--exclude-standard', '-z'
        ),
        'git ls-files'
    );
    my %seen;
    for my $path (@paths) {
        die "git produced duplicate worktree paths\n" if $seen{$path}++;
    }
    return @paths;
}

sub _validate_relative_path {
    my ($path) = @_;
    die 'invalid Git worktree path: ' . _display($path) . "\n"
      if $path eq '' || substr($path, 0, 1) eq '/';
    for my $component (split m{/}, $path, -1) {
        die 'unsafe Git worktree path: ' . _display($path) . "\n"
          if $component eq '' || $component eq '.' || $component eq '..';
    }
}

sub _join_relative {
    my ($prefix, $path) = @_;
    return $prefix eq '' ? $path : "$prefix/$path";
}

sub _assert_worktree_root {
    my ($repo, $is_submodule) = @_;
    my $git_admin = File::Spec->catfile($repo, '.git');
    my @git_admin_stat = lstat $git_admin;
    my $noun = $is_submodule ? 'submodule' : 'repository';
    die "$noun is not initialized at " . _display($repo) . "\n"
      if !@git_admin_stat;
    my $inside = _run_git($repo, 'rev-parse', '--is-inside-work-tree');
    my $prefix = _run_git($repo, 'rev-parse', '--show-prefix');
    $inside =~ s/\n\z//;
    $prefix =~ s/\n\z//;
    die 'path is not a Git worktree root: ' . _display($repo) . "\n"
      if $inside ne 'true' || $prefix ne '';
}

sub _collect_repository {
    my ($repo, $root_prefix, $active_worktrees) = @_;
    _assert_worktree_root($repo, $root_prefix ne '');
    my $real_repo = abs_path($repo);
    die 'cannot resolve worktree root: ' . _display($repo) . "\n"
      if !defined $real_repo;
    die 'recursive submodule worktree: ' . _display($repo) . "\n"
      if $active_worktrees->{$real_repo};
    local $active_worktrees->{$real_repo} = 1;

    my $modes = _index_modes($repo);
    my @leaves;
    for my $path (_listed_paths($repo)) {
        _validate_relative_path($path);
        my $absolute_path = File::Spec->catfile($repo, split m{/}, $path, -1);
        my $root_path = _join_relative($root_prefix, $path);
        if (($modes->{$path} // '') eq $GITLINK_MODE) {
            push @leaves,
              _collect_repository($absolute_path, $root_path, $active_worktrees);
            next;
        }

        my @metadata = lstat $absolute_path;
        die 'listed worktree leaf is missing: ' . _display($root_path) . "\n"
          if !@metadata;
        my $kind;
        if (-f _) {
            $kind = $REGULAR_FILE;
        }
        elsif (-l _) {
            $kind = $SYMLINK;
        }
        else {
            die 'unsupported worktree leaf type: ' . _display($root_path) . "\n";
        }
        push @leaves,
          {
            kind          => $kind,
            path          => $root_path,
            absolute_path => $absolute_path,
          };
    }
    return @leaves;
}

sub collect_leaves {
    my ($repo) = @_;
    $repo = File::Spec->rel2abs($repo);
    my @leaves = _collect_repository($repo, '', {});
    @leaves = sort { $a->{path} cmp $b->{path} } @leaves;
    my %seen;
    for my $leaf (@leaves) {
        die "submodule expansion produced duplicate root-relative paths\n"
          if $seen{$leaf->{path}}++;
    }
    return @leaves;
}

sub _u64 {
    my ($value, $label) = @_;
    die "$label is negative\n" if $value < 0;
    return pack('Q>', $value);
}

sub _stable_payload {
    my ($leaf) = @_;
    my @before = lstat $leaf->{absolute_path};
    die 'worktree leaf disappeared while hashing: ' . _display($leaf->{path}) . "\n"
      if !@before;

    my $payload;
    if ($leaf->{kind} == $REGULAR_FILE && -f _) {
        open my $source, '<:raw', $leaf->{absolute_path}
          or die 'cannot read worktree leaf '
          . _display($leaf->{path})
          . ": $!\n";
        local $/;
        $payload = <$source>;
        $payload = '' if !defined $payload;
        close $source
          or die 'cannot close worktree leaf '
          . _display($leaf->{path})
          . ": $!\n";
    }
    elsif ($leaf->{kind} == $SYMLINK && -l _) {
        $payload = readlink $leaf->{absolute_path};
        die 'cannot read symlink leaf ' . _display($leaf->{path}) . ": $!\n"
          if !defined $payload;
    }
    else {
        die 'worktree leaf changed type while hashing: '
          . _display($leaf->{path}) . "\n";
    }

    my @after = lstat $leaf->{absolute_path};
    die 'worktree leaf disappeared while hashing: ' . _display($leaf->{path}) . "\n"
      if !@after;
    # Compare mode, inode, size, mtime, and ctime. The operator must still quiesce edits
    # before an official run; this catches ordinary concurrent replacements and writes.
    for my $index (1, 2, 7, 9, 10) {
        die 'worktree leaf changed while hashing: ' . _display($leaf->{path}) . "\n"
          if $before[$index] != $after[$index];
    }
    return $payload;
}

sub fingerprint_records {
    my (@records) = @_;
    @records = sort { $a->[1] cmp $b->[1] } @records;
    my %seen;
    my $digest = Digest::SHA->new(256);
    $digest->add($DOMAIN);
    for my $record (@records) {
        my ($kind, $path, $payload) = @{$record};
        die "duplicate root-relative fingerprint path\n" if $seen{$path}++;
        die "unsupported fingerprint kind byte: $kind\n"
          if $kind != $REGULAR_FILE && $kind != $SYMLINK;
        _validate_relative_path($path);
        $digest->add(pack('C', $kind));
        $digest->add(_u64(length($path), 'path length'));
        $digest->add($path);
        $digest->add(_u64(length($payload), 'payload length'));
        $digest->add($payload);
    }
    return $digest->hexdigest;
}

sub fingerprint_leaves {
    my (@leaves) = @_;
    my @records = map {
        [$_->{kind}, $_->{path}, _stable_payload($_)]
    } sort { $a->{path} cmp $b->{path} } @leaves;
    return fingerprint_records(@records);
}

sub repository_fingerprint {
    my ($repo) = @_;
    my @leaves = collect_leaves($repo);
    return (fingerprint_leaves(@leaves), scalar @leaves);
}

sub _usage {
    my ($stream) = @_;
    print {$stream} <<'USAGE';
Usage: perl examples/scripts/source_tree_fingerprint.pl [OPTIONS]

  --repo PATH   Git worktree root to fingerprint (default: .)
  --describe    Print the exact versioned algorithm description
  --verbose     Print the fingerprinted leaf count to stderr
  --help        Show this help
USAGE
}

sub main {
    my (@arguments) = @_;
    my $repo = '.';
    my ($describe, $verbose, $help);
    my $parsed = GetOptionsFromArray(
        \@arguments,
        'repo=s'   => \$repo,
        'describe' => \$describe,
        'verbose'  => \$verbose,
        'help'     => \$help,
    );
    if (!$parsed || @arguments) {
        _usage(*STDERR);
        return 2;
    }
    if ($help) {
        _usage(*STDOUT);
        return 0;
    }
    if ($describe) {
        print "$ALGORITHM_DESCRIPTION\n";
        return 0;
    }

    my ($digest, $leaf_count);
    my $ok = eval {
        ($digest, $leaf_count) = repository_fingerprint($repo);
        1;
    };
    if (!$ok) {
        my $error = $@ || 'unknown fingerprint error';
        $error =~ s/\s+\z//;
        print STDERR "error: $error\n";
        return 1;
    }
    print STDERR "fingerprinted_leaves=$leaf_count\n" if $verbose;
    print "$digest\n";
    return 0;
}

unless (caller) {
    exit main(@ARGV);
}

1;
