package Parse::Snort::Strict;
use base qw(Parse::Snort);

use strict;
use warnings;
use Carp qw(croak);
use List::Util qw(any);
use Sub::Util qw(set_subname);

# valid values for rule parts
my $rule_parts_validation = {
  action => [qw( alert pass drop sdrop log activate dynamic reject )],
  proto => [qw( tcp udp ip icmp )],
  direction => [qw( -> <> <- )],
};

# method generator for simple rule parts, copypasta reduction
{
  my $generator = sub {
    # closures are teh awesome.
    my ($part,$value_ref) = @_;
    my $method = "SUPER::$part";

    return sub {
      my ($self,$value) = @_;

      # do validation
      croak "$value is not a valid rule $part" unless (any { $value eq $_ } @{ $value_ref });

      # call parent's method for value setting
      $self->$method($value);
    };
  };

  no strict qw(refs);
  while (my ($part,$value_ref) = each %$rule_parts_validation) {
    *{$part} = set_subname($part,$generator->($part,$value_ref));
  }
  use strict qw(refs);
}

1;
