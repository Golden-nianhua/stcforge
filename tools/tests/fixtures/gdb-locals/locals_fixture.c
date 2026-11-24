volatile unsigned int input;
volatile unsigned long sample;
volatile unsigned char marker;

unsigned int read_sample(void)
{
    return input;
}

unsigned int read_alternate(void)
{
    return input ^ 0xffff;
}

void initialized(void)
{
    unsigned int value = read_sample();
    marker = 11;
    sample = value;
}

void branch(void)
{
    unsigned int choice = 0;
    if (marker)
        choice = read_sample();
    else
        choice = read_alternate();
    marker = 12;
    sample = choice;
}

void no_initializer(void)
{
    unsigned int pending;
    marker = 13;
    pending = read_sample();
    marker = 14;
    sample = pending;
}

void loop(void)
{
    unsigned int outer = 0;
    for (;;) {
        outer = read_sample();
        unsigned int inner = read_alternate();
        marker = 15;
        sample = outer;
        sample = inner;
    }
}

void inner_scope(void)
{
    marker = 16;
    if (marker) {
        unsigned int bounded = read_sample();
        marker = 17;
        sample = bounded;
    }
    marker = 18;
}

void shadow(void)
{
    unsigned int duplicate = read_sample();
    if (marker) {
        unsigned int duplicate = read_alternate();
        sample = duplicate;
    }
    marker = 19;
    sample = duplicate;
}

void main(void)
{
    initialized();
    branch();
    no_initializer();
    inner_scope();
    shadow();
    loop();
}
