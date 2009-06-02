use ExtUtils::MakeMaker;

WriteMakefile (
	NAME		=> 'Apache2::AuthEnv',
	VERSION_FROM	=> 'lib/Apache2/AuthEnv.pm',
	DISTNAME	=> "Apache2-AuthEnv",
	dist		=> {COMPRESS => 'gzip', SUFFIX => 'gz'},

	PREREQ_PM  => {
		mod_perl2		=> 2,
		'Carp'			=> 1,
		'Data::Dumper'		=> 1,
		'ModPerl::Util'		=> 1,
		'Apache2::Module'	=> 1,
		'Apache2::Access'	=> 1,
		'Apache2::Log'		=> 1,
		'Apache2::ServerUtil'	=> 1,
		'Apache2::RequestUtil'	=> 1,
		'Apache2::RequestRec'	=> 1,
		'Apache2::Const'	=> 1,
		},

);
