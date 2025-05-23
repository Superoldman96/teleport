/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import React, { RefObject, useCallback, useLayoutEffect } from 'react';

/**
 * Transition is a helper for firing certain effects from Popover, as it's way easier to use them
 * this way than integrating with the component lifecycle.
 */
export function Transition({
  onEntering,
  enablePaperResizeObserver,
  paperRef,
  onPaperResize,
  children,
}: React.PropsWithChildren<{
  onEntering: () => void;
  enablePaperResizeObserver: boolean | undefined;
  paperRef: RefObject<HTMLElement | null>;
  onPaperResize: () => void;
}>) {
  // Note: useLayoutEffect to prevent flickering improperly positioned popovers.
  // It's especially noticeable on Safari.
  useLayoutEffect(onEntering, []);

  const resizeEffect = useCallback(() => {
    if (!paperRef.current || !enablePaperResizeObserver) return;

    const observer = new ResizeObserver(entries => {
      const entry = entries[0];
      if (entry.contentRect.height === 0) return;
      onPaperResize();
    });

    observer.observe(paperRef.current);

    return () => {
      observer.disconnect();
    };
  }, [onPaperResize, paperRef, enablePaperResizeObserver]);

  useLayoutEffect(resizeEffect, [resizeEffect]);

  return children;
}
