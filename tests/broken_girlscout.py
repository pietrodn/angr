import logging
import nose
import angr
import archinfo
import os

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))
l = logging.getLogger('angr.test_girlscout')

def main():
    file_path = "mipsel/fauxware"
    f = os.path.join(test_location, file_path)
    l.debug("Processing %s", f)

    # "Correct" data by using the default loader
    p_orig = angr.Project(f)

    p = angr.Project(
        f,
        load_options={
            'main_opts': {
                'backend': 'blob',
                'custom_arch': p_orig.arch,
            }
        }
    )
    # Call Girlscout
    gs = p.analyses.GirlScout(
        pickle_intermediate_results=False,
        perform_full_code_scan=False
    )

    # The base address detected by Girlscout should be equal to the original one
    nose.tools.assert_equal(gs.base_address, p_orig.loader.main_bin.get_min_addr())

if __name__ == "__main__":
    _debugging_modules = {
        'angr.analyses.girlscout'
    }
    _info_modules = {
        #'angr.analyses.girlscout'
    }
    _error_modules = {
        'angr.states'
    }
    for m in _debugging_modules:
        logging.getLogger(m).setLevel(logging.DEBUG)
    for m in _info_modules:
        logging.getLogger(m).setLevel(logging.INFO)
    for m in _error_modules:
        logging.getLogger(m).setLevel(logging.ERROR)
    main()
