.. _installation:

Installation
============

*ukt* can be installed using ``pip``:

.. code-block:: bash

    $ pip install ukt

Dependencies
------------

*ukt* has no dependencies. For development, you will need to install *cython*
in order to build the serializer extension.

Installing with git
-------------------

To install the latest version with git:

.. code-block:: bash

    $ git clone https://github.com/coleifer/ukt
    $ cd ukt/
    $ python setup.py install

Installing Kyoto Tycoon
-----------------------

If you're using a debian-based linux distribution, you can install using
``apt-get``:

.. code-block:: bash

    $ sudo apt-get install kyototycoon

Alternatively you can use the following Docker images:

.. code-block:: bash

    $ docker run -it --rm -v kyoto:/var/lib/kyototycoon -p 1978:1978 coleifer/kyototycoon

To build from source and read about the various command-line options, see the
project documentation:

* `Kyoto Tycoon documentation <http://fallabs.com/kyototycoon/>`_
