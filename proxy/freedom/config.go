package freedom

var strategy = [][]byte{
	//              name        strategy,   prefer, fallback
	{0, 0, 0}, //   AsIs        none,       /,      /
	{1, 0, 0}, //   UseIP       use,        both,   none
	{1, 4, 0}, //   UseIPv4     use,        4,      none
	{1, 6, 0}, //   UseIPv6     use,        6,      none
	{1, 4, 6}, //   UseIPv4v6   use,        4,      6
	{1, 6, 4}, //   UseIPv6v4   use,        6,      4
	{2, 0, 0}, //   ForceIP     force,      both,   none
	{2, 4, 0}, //   ForceIPv4   force,      4,      none
	{2, 6, 0}, //   ForceIPv6   force,      6,      none
	{2, 4, 6}, //   ForceIPv4v6 force,      4,      6
	{2, 6, 4}, //   ForceIPv6v4 force,      6,      4
}

func (c *Config) hasStrategy() bool {
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

func (c *Config) hasFallback() bool {
	return strategy[c.DomainStrategy][2] != 0
}

func (c *Config) fallbackIP4() bool {
	return strategy[c.DomainStrategy][2] == 4
}

func (c *Config) fallbackIP6() bool {
	return strategy[c.DomainStrategy][2] == 6
}
