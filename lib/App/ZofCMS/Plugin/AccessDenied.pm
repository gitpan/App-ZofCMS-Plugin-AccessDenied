package App::ZofCMS::Plugin::AccessDenied;

use warnings;
use strict;

our $VERSION = '0.0102';

sub new { return bless {}, shift }

sub process {
    my ( $self, $t, $q, $config ) = @_;

    $t->{plug_access_denied}
    = $t->{plug_access_denied}->( $t, $q, $config )
        if ref $t->{plug_access_denied} eq 'CODE';

    $config->conf->{plug_access_denied}
    = $config->conf->{plug_access_denied}->( $t, $q, $config )
        if ref $config->conf->{plug_access_denied} eq 'CODE';

    my %conf = (
        role            => sub { $_[0]->{d}{user}{role} },
        separator       => qr/\s*,\s*/,
        key             => 'access_roles',
        redirect_page   => '/access-denied',
        master_roles    => 'admin',
        no_exit         => 0,

        %{ delete $config->conf->{plug_access_denied} || {} },
        %{ delete $t->{plug_access_denied}            || {} },
    );

    return
        unless defined $t->{ $conf{key} }
            and length $t->{ $conf{key} };

    my $user_role_raw = $conf{role}->( $t, $q, $config );
    $user_role_raw = $user_role_raw->( $t, $q, $config )
        if ref $user_role_raw eq 'CODE';

    my $user_roles = prepare_user_roles( \%conf, $user_role_raw );

    for ( split /$conf{separator}/, $conf{master_roles} ) {
        return 1
            if $user_roles->{$_};
    }

    for ( split /$conf{separator}/, $t->{ $conf{key} } ) {
        return 1
            if exists $user_roles->{$_};
    }

    print $config->cgi->redirect( $conf{redirect_page} );

    exit
        unless $conf{no_exit};
}

sub prepare_user_roles {
    my ( $conf, $user_role_raw ) = @_;
    my %roles;

    if ( ref $user_role_raw eq 'ARRAY' ) {
        %roles = map +( $_ => 1 ), @$user_role_raw;
    }
    elsif ( ref $user_role_raw eq 'HASH' ) {
        %roles = map +( $_ => 1 ), keys %$user_role_raw;
    }
    else {
        %roles
        = map +( $_ => 1 ), split /$conf->{separator}/, $user_role_raw;
    }

    return \%roles;
}


1;
__END__

=encoding utf8

=head1 NAME

App::ZofCMS::Plugin::AccessDenied - ZofCMS plugin to restrict pages based on user access roles

=head1 SYNOPSIS

    plugins => [
        { AccessDenied => 2000 },
    ],

    # this key and all of its individual arguments are optional
    # ... default values are shown here
    plug_access_denied => {
        role            => sub { $_[0]->{d}{user}{role} },
        separator       => qr/\s*,\s*/,
        key             => 'access_roles',
        redirect_page   => '/access-denied',
        master_roles    => 'admin',
        no_exit         => 0,
    },

    # this user has three roles; but this page requires a different one
    d => { user => { role => 'foo, bar,baz', }, },
    access_roles => 'bez',

=head1 DESCRIPTION

The module is a plugin for L<App::ZofCMS> that provides means to
restrict access to various pages. It's designed to work in conjunction
with L<App::ZofCMS::Plugin::UserLogin> plugin; however, the use of that
plugin is not required.

This documentation assumes you've read L<App::ZofCMS>, 
L<App::ZofCMS::Config> and L<App::ZofCMS::Template>

=head1 FIRST-LEVEL ZofCMS TEMPLATE AND MAIN CONFIG FILE KEYS

=head2 C<plugins>

    plugins => [
        { AccessDenied => 2000 },
    ],

B<Mandatory>. You need to include the plugin in the list of plugins to
execute.

=head2 C<plug_access_denied>

    # default values shown
    plug_access_denied => {
        role            => sub { $_[0]->{d}{user}{role} },
        separator       => qr/\s*,\s*/,
        key             => 'access_roles',
        redirect_page   => '/access-denied',
        master_roles    => 'admin',
        no_exit         => 0,
    },

    # or
    plug_access_denied => sub {
        my ( $t, $q, $config ) = @_;
        return $hashref_to_assign_to_plug_access_denied_key;
    },

B<Optional>.
Takes either a hashref or a subref as a value. If not specified, B<plugin
will still run>, and all the defaults will be assumed. If subref is
specified, its return value will be assigned to C<plug_access_denied> as if
it was already there. The C<@_> of the subref will contain C<$t>, C<$q>,
and C<$config> (in that order): where C<$t> is ZofCMS Tempalate hashref,
C<$q> is query parameters hashref, and C<$config> is
L<App::ZofCMS::Config> object. Possible keys/values for the hashref are as
follows:

=head3 C<role>

    plug_access_denied => {
        role => sub { $_[0]->{d}{user}{role} },
    ...

B<Optional>. Takes a subref as a value. This argument tells the plugin
the access roles the current user (visitor) possesses and based on these, 
the access to the page will be either granted or denied. The C<@_> will
contain C<$t>, C<$q>, and C<$config> (in that order), where C<$t> is ZofCMS
Template hashref, C<$q> is query parameter hashref, and C<$config> is
the L<App::ZofCMS::Config> object. B<Defaults to:>
C<< sub { $_[0]->{d}{user}{role} } >> (i.e. attain the value from the
C<< $t->{d}{user}{role} >>). The subref must return one of the following:

=head4 a string

    plug_access_denied => {
        role => sub { return 'foo, bar, baz' },
    ...

If the sub returns a string, the plugin will take it as containing
one or more roles that the user (visitor of the page) has. Multiple roles
must be separated using C<separator> (see below).

=head4 an arrayref

    plug_access_denied => {
        role => sub { return [ qw/foo  bar  baz/ ] },
    ...

If sub returns an arrayref, each element of that arrayref will be assumed
to be one role.

=head4 a hashref

    plug_access_denied => {
        role => sub { return { foo => 1, bar => 1 } },
    ...

If hashref is returned, plugin will assume that the B<keys> of that hashref
are the roles; plugin doesn't care about the values.

=head3 C<separator>

    plug_access_denied => {
        separator => qr/\s*,\s*/,
    ...

B<Optional>. Takes a regex (C<qr//>) as a value. The value will be regarded
as a separator for page's access roles (listed in C<key> key, see
below), the value in C<role> (see above) if that argument is set to a
string, as well as the value of C<master_roles> argument (see below). 
B<Defaults to:> C<qr/\s*,\s*/>

=head3 C<key>

    plug_access_denied => {
        key => 'access_roles',
    ...

B<Optional>. Takes a string as a value. Specifies the key, inside C<{t}>
ZofCMS Template hashref's special key, under which a string with page's
roles is located.
Multiple roles must be separated with C<separator> (see above).
User must possess at least one of these roles in order to be allowed to
view the current page. B<Defaults to:> C<access_roles> (i.e.
C<< $t->{t}{access_roles} >>)

=head3 C<redirect_page>

    plug_access_denied => {
        redirect_page => '/access-denied',
    ...

B<Optional>. Takes a URI as a value. If access is denied to the visitor,
they will be redirected to URI specified by C<redirect_page>. B<Defaults
to:> C</access-denied>

=head3 C<master_roles>

    plug_access_denied => {
        master_roles => 'admin',
    ...

B<Optional>. Takes the string a value that contains "master" roles. If the
user has any of the roles specified in C<master_roles>, access to the page
will be B<granted> regardless of what the page's required roles (specified 
via C<key> argument) are. To disable C<master_roles>, use empty string. To 
specify several roles, separate them with your C<separator> (see above).
B<Defaults to:> C<admin>

=head3 C<no_exit>

    plug_access_denied => {
        no_exit => 0,
    ...

B<Optional>. Takes either true or false values as a value. If set to
a false value, the plugin will call C<exit()> after it tells the browser
to redirect unauthorized user to C<redirect_page> (see above); otherwise,
the script will continue to run, however, note that you B<will no longer
be able to "interface" with the user> (i.e. if some later plugin dies, user
will be already at the C<redirect_page>). B<Defaults to:> C<0> (false)

=head1 AUTHOR

'Zoffix, C<< <'zoffix at cpan.org'> >>
(L<http://haslayout.net/>, L<http://zoffix.com/>, L<http://zofdesign.com/>)

=head1 BUGS

Please report any bugs or feature requests to C<bug-app-zofcms-plugin-accessdenied at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=App-ZofCMS-Plugin-AccessDenied>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc App::ZofCMS::Plugin::AccessDenied

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=App-ZofCMS-Plugin-AccessDenied>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/App-ZofCMS-Plugin-AccessDenied>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/App-ZofCMS-Plugin-AccessDenied>

=item * Search CPAN

L<http://search.cpan.org/dist/App-ZofCMS-Plugin-AccessDenied/>

=back



=head1 COPYRIGHT & LICENSE

Copyright 2010 'Zoffix, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.


=cut

