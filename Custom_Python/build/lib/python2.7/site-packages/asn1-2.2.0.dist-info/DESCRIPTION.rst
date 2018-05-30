

========
Overview
========

Python-ASN1 is a simple ASN.1 encoder and decoder for Python 2.6+ and 3.3+.

Features
========

- Support BER (parser) and DER (parser and generator) encoding
- 100% python, compatible with version 2.6, 2.7, 3.3 and higher
- Can be integrated by just including a file into your project


Dependencies
==============

Python-ASN1 relies on `Python-Future <http://python-future.org>`_ for Python 2 and 3 compatibility. To install Python-Future:

.. code-block:: sh

  pip install future


How to install Python-asn1
==========================

Install from PyPi with the following:

.. code-block:: sh

  pip install asn1

or download the repository from `GitHub <https://github.com/andrivet/python-asn1>`_ and install with the following:

.. code-block:: sh

  python setup.py install

You can also simply include ``asn1.py`` into your project.


How to use Python-asn1
======================

.. note:: You can find more detailed documentation on the `Usage`_ page.

.. _Usage: usage.html

Encoding
--------

If you want to encode data and retrieve its DER-encoded representation, use code such as:

.. code-block:: python

  import asn1

  encoder = asn1.Encoder()
  encoder.start()
  encoder.write('1.2.3', asn1.ObjectIdentifier)
  encoded_bytes = encoder.output()


Decoding
--------

If you want to decode ASN.1 from DER or BER encoded bytes, use code such as:

.. code-block:: python

  import asn1

  decoder = asn1.Decoder()
  decoder.start(encoded_bytes)
  tag, value = decoder.read()


Documentation
=============

The complete documentation is available on Read The Docs:

`python-asn1.readthedocs.io <https://python-asn1.readthedocs.io/en/latest/>`_


License
=======

Python-ASN1 is free software that is made available under the MIT license.
Consult the file LICENSE that is distributed together with this library for
the exact licensing terms.

Copyright
=========

The following people have contributed to Python-ASN1. Collectively they own the copyright of this software.

* Geert Jansen (geert@boskant.nl): `original implementation <https://github.com/geertj/python-asn1>`_.
* Sebastien Andrivet (sebastien@andrivet.com)

Changelog
=========

2.1.1 (2017-10-30)

* Fix a bug (#9): two's complement corner case with values such as -32769. Add new test cases to test them.

2.1.0 (2016-12-18)
------------------

* Add more documentation
* Use (simulated) enumerations
* Add Python 2.6 in automated checks and tests
* Add type hints (for static checking) and fix some code

2.0.0 (2016-12-16)
------------------

* First public release by Sebastien Andrivet
* Support both python 2 and 3 (with Python-Future)
* All strings are now in unicode
* Add more ASN.1 tags (like PrintableString)
* Fix errors in the example (dump.py)
* Code reorganization

0.9 (2011-05-18)
----------------

* Initial public release by Geert Jansen


