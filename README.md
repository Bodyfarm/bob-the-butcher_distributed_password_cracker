# bob-the-butcher distributed password cracker
bob-the-butcher archive.

http://btb.banquise.net
http://btb.banquise.net/bin/bob-the-butcher-0.7.1.tar.gz
http://www.openwall.com/lists/john-users/2009/06/11/2

http://download.openwall.net/pub/projects/john/contrib/parallel/btb/

Date: Thu, 22 Dec 2005 17:04:09 +0100
From: Simon Marechal <simon@...quise.net>
To: john-users@...ts.openwall.com
Subject: bob the butcher distributed password cracker

Hello,

	As some people would like to see a distributed password cracker, i post
here a link to this tool i wrote to just do that (and more).

	You can download it there:
	http://www.banquise.net/misc/bob-the-butcher.html

	The name is a reference to john, because i ripped the format files and
ciphers code.

	For now it quite sucks. It's buggy, and lacks the following features:
	* smart password generation algorithm. It just brutes forces all
passwords from a to z. Currently a single computer running john is more
likely to crack passwords than 10 computers running bob.
	* salts based mutualisation. The goal of this project is to provide a
single platform to crack multiple passwords / hash files at the same
time. A good optimization would be to aggregate all of them based on
cipher types and salts.

	I hope this post is not (totally) off topic, and that some brave
testers will iron it out. It only works on x86 mmx (linux / cygwin) for
now and requires libevent. Moreover, if somebody understands why the
ripped DES code doesn't work for x86 without mmx, that would be great.

	Final warning : this is ALPHA, I wrote it, and there is a network
daemon. Only use it on a trusted network.
