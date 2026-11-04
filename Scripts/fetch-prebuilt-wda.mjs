/**
 * Copyright (c) 2015-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 *
 * Hardened copy: the upstream script downloaded prebuilt WebDriverAgent
 * zip archives from GitHub releases. That download is removed. Build the
 * runner from this source in Xcode. See BUILD.md.
 */

console.error(
  'Refusing to download prebuilt WebDriverAgent archives. Build the runner from this source in Xcode. See BUILD.md.',
);
process.exit(1);
