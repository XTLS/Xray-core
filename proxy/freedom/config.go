package freedom

var strategy = [][]byte{
	//				name 		use/force,	prefer,	fallback
	{0, 0, 0}, //	AsIs		none,		none,	none
	{1, 0, 0}, //	UseIP		use,		none,	none
	{1, 4, 0}, //	UseIPv4		use,		4
	{1, 6, 0}, //	UseIPv6		use,		6
	{1, 4, 6}, //	UseIPv4v6	use,		4,	6
	{1, 6, 4}, //	UseIPv6v4	use,		6,	4
	{2, 0, 0}, //	ForceIP		force,		none,	none
	{2, 4, 0}, //	ForceIPv4	force,		4
	{2, 6, 0}, //	ForceIPv6	force,		6
	{2, 4, 6}, //	ForceIPv4v6	force,		4,	6
	{2, 6, 4}, //	ForceIPv6v4	force,		6,	4
}

func (c *Config) useIP() bool {
	return strategy[c.DomainStrategy][0] != 0
}

func (c *Config) forceIP() bool {
	return strategy[c.DomainStrategy][0] == 2
}

func (c *Config) preferIP4() bool {
	return strategy[c.DomainStrategy][1] == 4 || strategy[c.DomainStrategy][1] == 0
}

func (c *Config) preferIP6() bool {
	return strategy[c.DomainStrategy][1] == 6 || strategy[c.DomainStrategy][1] == 0
}

func (c *Config) fallbackIP() bool {
	return strategy[c.DomainStrategy][2] == 4 || strategy[c.DomainStrategy][2] == 6
}

func (c *Config) fallbackIP6() bool {
	return strategy[c.DomainStrategy][2] == 6
}
