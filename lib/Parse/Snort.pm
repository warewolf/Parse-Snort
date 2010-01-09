package Parse::Snort;

use strict;
use warnings;
use base qw(Class::Accessor);
use List::Util qw(first);
use Carp qw(carp);

=head1 NAME

Parse::Snort - Parse and create Snort rules

=head1 VERSION

Version 0.01

=head1 SYNOPSIS

    use Parse::Snort;

    my $rule = Parse::Snort->new(
      action => 'alert',
      proto => 'tcp',
      src => '$HOME_NET', src_port => 'any',
      direction => '->'
      dst =>'$EXTERNAL_NET', dst_port => 'any'
    );

    $rule->action("pass");

    $rule->opts(
	[ 'depth' => 50 ],
	[ 'offset' => 0 ],
	[ 'content' => "perl6" ],
	[ "nocase" ]
    );

    my $rule = Parse::Snort->new();
    $rule->parse('pass tcp $HOME_NET any -> $EXTERNAL_NET 6667;');
    $rule->msg("IRC server");
    my $rule_string = $rule->as_string;
);

=cut 

our $VERSION                = '0.01';
our @RULE_ACTIONS           = qw/ alert pass drop sdrop log /;
our @RULE_ELEMENTS_REQUIRED =
  qw/ action proto src src_port direction dst dst_port /;
our @RULE_ELEMENTS = ( @RULE_ELEMENTS_REQUIRED, 'opts' );

__PACKAGE__->mk_accessors(@RULE_ELEMENTS);

=head1 METHODS

The following methods can be used to read or modify parts of a rule.

=over 4

=item B<new($rule_string)>, B<new($rule_element_ref)>

This function will create a new C<Parse::Snort> object.  You may pass nothing, a string containing a properly formatted Snort rule, or a gash reference of rule elements and options.

=over 4

=item B<$rule_string>

  $rule_string = 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"perl 6 download detected\; may the world rejoice!";depth:150; offset:0; content:"perl-6.0.0"; nocase;)'


=item B<$rule_element_hashref>

  $rule_element_hashref = {
    action => 'alert',
    proto => 'tcp',
    src => '$EXTERNAL_NET', src_port => 'any',
    direction => '->',
    dst => '$HOME_NET', dst_port => 'any',
    opts => [
    	[ 'msg' => ':"perl 6 download detected\; may the world rejoice!"' ],
    	[ 'depth' => 150 ],
    	[ 'offset' => 0 ].
    	[ 'content' => 'perl-6.0.0' ],
    	[ 'nocase' ],
    ],
      
  };

=back

=cut

sub new {
    my ( $class, $fields ) = @_;
    #my ($class) = ref $proto || $proto;

    my $self = {};

    # make a copy of $fields.
    bless $self, $class;
    $self->_init($fields);
}

sub _init {
    my ( $self, $data ) = @_;

    if ( ref($data) eq "HASH" ) {
        while ( my ( $method, $val ) = each %$data ) {
            $self->$method($val);
        }
    } elsif ( defined($data) ) {
        $self->parse($data);
    }
    return $self;
}

=item B<parse($rule_string)>

The parse method can be used to parse a snort rule string after new() has been called.  The rule object will be populated with the parsed version of $rule_string, overwriting any previously defined values in the object.

  $rule_object->parse($rule_string);

=cut

sub parse {
    my ( $self, $rule ) = @_;

    my @values = split( m/ /, $rule, scalar @RULE_ELEMENTS );    # no critic

    for my $i ( 0 .. $#RULE_ELEMENTS ) {
        my $meth = $RULE_ELEMENTS[$i];
        $self->$meth( $values[$i] );
    }
}

=back

=head2 METHODS FOR RULE ELEMENTS

The following methods read or modify the various rule elements.

=over 4

=item B<action> 

The rule action.  Generally one of the following: C<alert>, C<pass>, C<drop>, C<sdrop>, or C<log>.

=item B<proto> 

The protocol of the rule.  Generally one of the following: C<tcp>, C<udp>, C<ip>, or C<icmp>.

=item B<src> 

The source IP address for the rule.  Generally a dotted decimal IP address, Snort $HOME_NET variable, or CIDR block notation.

=item B<src_port> 

The source port for the rule.  Generally a static port, or a contigious range of ports.

=item B<direction> 

The direction of the rule.  One of the following: C<->> C<<>> or C<<->.

=item B<dst> 

The destination IP address for the rule.  Same format as C<src>

=item B<dst_port> 

The destination port for the rule.  Same format as C<src>

=item B<opts($opts_array_ref)>, B<opts($opts_string)>

The opts method can be used to read existing options of a parsed rule, or set them.  The method takes two forms of arguments, either an Array of Arrays, or a rule string.

=over 4

=item B<$opts_array_ref>

  $opts_array_ref = [
       [ 'msg' => ':"perl 6 download detected\; may the world rejoice!"' ],
       [ 'depth' => 150 ],
       [ 'offset' => 0 ].
       [ 'content' => 'perl-6.0.0' ],
       [ 'nocase' ],
  ]

=item B<$opts_string>

  $opts_string='(msg:"perl 6 download detected\; may the world rejoice!";depth:150; offset:0; content:"perl-6.0.0"; nocase;)';

The parenthesis surround the series of C<key:value;> pairs are optional.

=back

=cut

sub opts {
    my ( $self, $args ) = @_;

    if ($args) {

        # setting
        if ( ref($args) eq "ARRAY" ) {

            # list interface:
            # ([depth => 50], [offset => 0], [content => "perl6"], ["nocase"])
            $self->set( 'opts', $args );
        } else {

            # string interface
            # 'depth:50; offset:0; content;"perl\;6"; nocase;'
            if ( $args =~ m/^\(/ ) {
                $args =~ s/^\((.+)\)$/$1/;
            }
            my @set =
              map { [ split( m/:/, $_, 2 ) ] }
              $args =~ m/\s*((?:\\.|[^;])+)(?:;|$)\s*/g;
            $self->set( 'opts', @set );
        }
    } else {

        # getting
        return $self->get('opts');
    }
}

sub _opt_accessor {
    my $opt = shift;
    return sub {
        my ( $self, $val ) = @_;

        # find the (hopefully) pre-existing option in the opts AoA
        my $element;

        #if ( defined $self->get('opts') and ref $self->get('opts') ) {
        if ( defined $self->get('opts') ) {
            $element = first { $_->[0] eq $opt } @{ $self->get('opts') };
        }

        if ( ref($element) ) {

            # preexisting
            if ($val) { $element->[1] = $val; }
            else { return $element->[1]; }
        } else {

            # doesn't exist
            if ($val) {

                # setting
                if ( scalar $self->get('opts') ) {

                    # other opts exist, tack it on the end
                    $self->set(
                        'opts',
                        @{ $self->get('opts') },
                        [ $opt, $val ]
                    );
                } else {

                    # blank slate, create the AoA
                    $self->set( 'opts', [ [ $opt, $val ] ] );
                }
            } else {

                # getting
                return;
            }
        }
      }
}

# helper accessors that poke around inside rule options

*sid       = _opt_accessor('sid');
*rev       = _opt_accessor('rev');
*msg       = _opt_accessor('msg');
*classtype = _opt_accessor('classtype');

=back

=head2 HELPER METHODS FOR OPTIONS

=over 4

=item B<sid>, B<rev>, B<msg>, B<classtype> 

The C<sid>, C<rev>, C<msg>, and C<classtype> methods allow direct access to the rule option of the same name

  my $sid = $rule_obj->sid(); # reads the sid of the rule
  $rule_obj->sid($sid); # sets the sid of the rule
  ... etc ...

=item B<references>

The C<references> method returns an array reference of the references in the rule.  Each reference is an array, in [ 'reference_type' => 'reference_value' ] format.  To modify references, use the C<opts> method.

=cut 

sub references {
    my ($self) = shift;
    my @references =
      map { [ split( m/,/, $_->[1], 2 ) ] }
      grep { $_->[0] eq "reference" } @{ $self->get('opts') };
    return \@references;
}

=item B<as_string>

The C<as_string> method returns a string that matches the normal Snort rule form of the object.  This is what you want to use to write a rule to an output file that will be read by Snort.

=cut

sub as_string {
    my $self = shift;
    my $ret;
    my @missing;

    # we may be incomplete
    if ( @missing = grep { $_ } map { exists( $self->{$_} ) ? undef : $_ } @RULE_ELEMENTS_REQUIRED)
    { carp sprintf( "Missing required rule element(s): %s", join( " ", @missing ) ); }

    if (! scalar @missing)
    { $ret .= sprintf( "%s %s %s %s %s %s %s", @$self{@RULE_ELEMENTS} ); }

    if ( defined $self->get('opts') )
    { $ret .= sprintf( " (%s)", join( " ", map { $_->[1] ? "$_->[0]:$_->[1];" : "$_->[0];" } @{ $self->get('opts') } )); }

    return ! scalar @missing ? $ret : "";
}

=back

=head1 AUTHOR

Richard G Harman Jr, C<< <perl-cpan at richardharman.com> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-parse-snort at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Parse-Snort>.
I will be notified, and then you' ll automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Parse::Snort

You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Parse-Snort>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Parse-Snort>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Parse-Snort>

=item * Search CPAN

L<http://search.cpan.org/dist/Parse-Snort>

=back

=head1 DEPENDENCIES

L<Test::More>, L<Class::Accessor>, L<List::Util>

=head1 ACKNOWLEDGEMENTS

MagNET #perl for putting up with me :)

=head1 COPYRIGHT & LICENSE

Copyright 2007 Richard Harman, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

!!'mtfnpy!!';
