#!/bin/bash

move clean
move check 
move publish  --ignore-breaking-changes

move unit-test src unittest -f test_zero_copy_decode

