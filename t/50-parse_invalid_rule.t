use strict;
use warnings;

use Test::More;
use Test::Exception;
use Parse::Snort;

my $text_rule = 'tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any ()';

my @valid = qw(
    alert
    pass
    drop
    sdrop
    log
    dynamic
    activate
    reject
);

foreach my $action (@valid) {
    my $snort = Parse::Snort->new();
    my $rule = "$action $text_rule";
    lives_ok(
        sub {
            $snort->parse($rule);
        },
        "$action is valid",
    );
}

foreach my $action (qw(allert slog)) {
    my $snort = Parse::Snort->new();
    my $rule = "$action $text_rule";
    throws_ok(
        sub {
            $snort->parse($rule);
        },
        qr/^Unable to parse rule, unknown action: $action/,
        "Unable to parse rule with action: $action",
    );
}

done_testing();
