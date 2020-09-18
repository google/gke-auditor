# How to Contribute

We'd love to accept your patches and contributions to this project. There are
just a few small guidelines you need to follow.

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution;
this simply gives us permission to use and redistribute your contributions as
part of the project. Head over to <https://cla.developers.google.com/> to see
your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

## Code reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose.
Consult [GitHub Help](https://help.github.com/articles/about-pull-requests/)
for more information on using pull requests.

## Community Guidelines

This project follows [Google's Open Source Community Guidelines](https://opensource.google/conduct)

## Code Style

All code must adhere to the [Google Java Style Guide](https://google.github.io/styleguide/javaguide.html).

## How to write a Detector

- Implement the [DetectorConfig](TODO) interface, referring to the Javadoc for
instructions

- Add the detector into the appropriate group of detectors in [Detectors](TODO)

  - Adding a new group of detectors will require changes to [RunnerConfig](TODO)
and [DetectorRunner](TODO)

- Add the detector into the help section of the tool in [Main](Main)

- Add Unit tests