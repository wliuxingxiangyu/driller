# -*- coding: utf-8 -*-

import os
import sys
import nose
import logging

import angr
import driller


l = logging.getLogger("driller.driller")

# https://github.com/wliuxingxiangyu/binaries
bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
# bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../hz_bins'))
# bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../cgc-bins'))

def test_drilling_cgc():
    """
    Test drilling on the cgc binary, palindrome 回文.
    """
    binary = "tests/cgc/sc1_0b32aa01_01"
    # binary = "hi"
    # binary = "all_patched/KPRCA_00110_patched"

    # fuzzbitmap says every transition is worth satisfying.
    # input_str=AAAA. fuzz_bitmap="\xff"*65535.  tag="whatever~"。
    d = driller.Driller(os.path.join(bin_location, binary), b"AAAA", b"\xff"*65535, "whatever~")

    new_inputs = d.drill()
    print("hz- new_inputs: %s " %  new_inputs )

    nose.tools.assert_equal(len(new_inputs), 7)

    # Make sure driller produced a new input which hits the easter egg 复活节彩蛋.
    # any 只有存在 一个以'^'开头的输入， 就为true.
    nose.tools.assert_true(any(filter(lambda x: x[1].startswith(b'^'), new_inputs)))


def test_simproc_drilling():
    """
    Test drilling on the cgc binary palindrome with simprocedures.
    """

    binary = "tests/i386/driller_simproc"
    memcmp = angr.SIM_PROCEDURES['libc']['memcmp']() # memcmp(): 比较内存前n个字节
    simprocs = {0x8048200: memcmp}

    # fuzzbitmap says every transition is worth satisfying.
    # input_str="A"*0x80. fuzz_bitmap="\xff"*65535.  tag="whatever~".  hooks=simprocs.
    d = driller.Driller(os.path.join(bin_location, binary), b"A"*0x80, b"\xff"*65535, "whatever~", hooks=simprocs)

    new_inputs = d.drill()
    print("hz- new_inputs: %s " %  new_inputs )

    # Make sure driller produced a new input which satisfies the memcmp.
    # any 只有存在 一个以the_secret_password开头的输入， 就为true.
    password = b"the_secret_password_is_here_you_will_never_guess_it_especially_since_it_is_going_to_be_made_lower_case"
    nose.tools.assert_true(any(filter(lambda x: x[1].startswith(password), new_inputs)))


def run_all():
    def print_test_name(name):
        print('#' * (len(name) + 8))
        print('###', name, '###')
        print('#' * (len(name) + 8))

    functions = globals()
    print("hz- functions: %s " %  functions)
    # filter 如果函数名以test_ 开头，则加入all_functions字典。
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    print("hz- all_functions: %s " %  all_functions )

    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            print_test_name(f)
            all_functions[f]()


if __name__ == "__main__":
    l.setLevel('DEBUG')

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
