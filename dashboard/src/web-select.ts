/** Web presentation for selects; native fields retain form values and validation. */
interface SelectView {
  source: HTMLSelectElement;
  wrapper: HTMLSpanElement;
  trigger: HTMLButtonElement;
  menu: HTMLDivElement;
  signature: string;
  error: HTMLSpanElement;
}

const views = new WeakMap<HTMLSelectElement, SelectView>();
let active: SelectView | null = null;
let sequence = 0;
let search = '';
let searchedAt = 0;

function labelFor(source: HTMLSelectElement): string {
  if (source.getAttribute('aria-label')) return source.getAttribute('aria-label')!;
  const labelled = source.getAttribute('aria-labelledby')?.split(/\s+/).map(id => document.getElementById(id)?.textContent ?? '').join(' ').trim();
  if (labelled) return labelled;
  const label = source.labels?.[0]?.cloneNode(true) as HTMLElement | undefined;
  label?.querySelectorAll('input, select, textarea, button, .web-select, .field-note').forEach(node => node.remove());
  return label?.textContent?.trim() || source.name || 'Choose an option';
}

function close(restoreFocus = false): void {
  const view = active;
  if (!view) return;
  active = null;
  view.trigger.setAttribute('aria-expanded', 'false');
  if (typeof view.menu.hidePopover === 'function' && view.menu.matches(':popover-open')) view.menu.hidePopover();
  view.menu.hidden = true;
  if (view.wrapper.isConnected) view.wrapper.append(view.menu);
  else view.menu.remove();
  if (restoreFocus && view.trigger.isConnected) view.trigger.focus({preventScroll: true});
}

function position(view: SelectView): void {
  const rect = view.trigger.getBoundingClientRect();
  const gap = 8;
  const below = window.innerHeight - rect.bottom - gap;
  const above = rect.top - gap;
  const upward = below < 160 && above > below;
  const height = Math.max(44, Math.min(288, upward ? above : below));
  Object.assign(view.menu.style, {
    left: `${Math.max(gap, Math.min(rect.left, window.innerWidth - rect.width - gap))}px`,
    width: `${Math.min(rect.width, window.innerWidth - gap * 2)}px`,
    maxHeight: `${height}px`,
    top: upward ? 'auto' : `${rect.bottom + gap}px`,
    bottom: upward ? `${window.innerHeight - rect.top + gap}px` : 'auto',
  });
}

function options(view: SelectView): HTMLButtonElement[] {
  return [...view.menu.querySelectorAll<HTMLButtonElement>('[role="option"]')].filter(option => !option.disabled);
}

function focusOption(view: SelectView, index: number): void {
  const choices = options(view);
  const option = choices[(index + choices.length) % choices.length];
  option?.focus({preventScroll: true});
  if (option) {
    // Scroll only the list; scrollIntoView also scrolls the enclosing dialog.
    const top = option.getBoundingClientRect().top - view.menu.getBoundingClientRect().top + view.menu.scrollTop;
    const bottom = top + option.offsetHeight;
    if (top < view.menu.scrollTop) view.menu.scrollTop = top;
    else if (bottom > view.menu.scrollTop + view.menu.clientHeight)
      view.menu.scrollTop = bottom - view.menu.clientHeight;
  }
}

function open(view: SelectView, edge?: 'first' | 'last'): void {
  if (view.source.disabled) return;
  close();
  active = view;
  search = '';
  update(view);
  // Dialogs already occupy the top layer. A nested popover hides their
  // backdrop/content in WKWebView, so use a fixed sibling of the form there.
  const dialog = view.source.closest('dialog');
  if (dialog) view.menu.removeAttribute('popover');
  else if (typeof view.menu.showPopover === 'function') view.menu.setAttribute('popover', 'manual');
  (dialog ?? document.body).append(view.menu);
  view.menu.hidden = false;
  position(view);
  if (view.menu.hasAttribute('popover')) view.menu.showPopover();
  view.trigger.setAttribute('aria-expanded', 'true');
  const choices = options(view);
  const selected = choices.findIndex(option => option.getAttribute('aria-selected') === 'true');
  focusOption(view, edge === 'last' ? choices.length - 1 : edge === 'first' ? 0 : Math.max(0, selected));
}

function choose(view: SelectView, option: HTMLButtonElement): void {
  if (option.disabled) return;
  const index = Number(option.dataset.index);
  const changed = view.source.selectedIndex !== index;
  view.source.selectedIndex = index;
  view.trigger.removeAttribute('aria-invalid');
  close(true);
  update(view);
  if (changed) {
    view.source.dispatchEvent(new Event('input', {bubbles: true}));
    view.source.dispatchEvent(new Event('change', {bubbles: true}));
  }
}

function keydown(event: KeyboardEvent, view: SelectView): void {
  const choices = options(view);
  const index = choices.indexOf(document.activeElement as HTMLButtonElement);
  if (event.key === 'Escape' && active === view) {
    event.preventDefault(); event.stopPropagation(); close(true);
  } else if (event.key === 'Tab' && active === view) {
    // Restore trigger before normal Tab moves to the next form control.
    close(true);
  } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault();
    if (active !== view) open(view);
    else focusOption(view, index + (event.key === 'ArrowDown' ? 1 : -1));
  } else if (event.key === 'Home' || event.key === 'End') {
    event.preventDefault();
    if (active !== view) open(view, event.key === 'Home' ? 'first' : 'last');
    else focusOption(view, event.key === 'Home' ? 0 : choices.length - 1);
  } else if ((event.key === 'Enter' || event.key === ' ') && active !== view) {
    event.preventDefault(); open(view);
  } else if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey && event.key !== ' ') {
    event.preventDefault();
    if (active !== view) open(view);
    search = Date.now() - searchedAt > 700 ? event.key : search + event.key;
    searchedAt = Date.now();
    const match = options(view).findIndex(option => option.textContent?.trim().toLowerCase().startsWith(search.toLowerCase()));
    if (match >= 0) focusOption(view, match);
  }
}

function update(view: SelectView): void {
  const {source, trigger, menu} = view;
  const name = labelFor(source);
  const signature = JSON.stringify([name, source.disabled, source.required, source.selectedIndex,
    source.getAttribute('aria-describedby'), [...source.options].map(option => [option.text, option.value, option.disabled, option.hidden, option.parentElement instanceof HTMLOptGroupElement && option.parentElement.disabled])]);
  if (signature === view.signature) return;
  view.signature = signature;
  trigger.setAttribute('aria-label', name);
  trigger.setAttribute('aria-required', String(source.required));
  trigger.disabled = source.disabled;
  const described = source.getAttribute('aria-describedby');
  trigger.setAttribute('aria-describedby', [described, view.error.id].filter(Boolean).join(' '));
  if (source.validity.valid) {
    view.error.textContent = '';
    trigger.removeAttribute('aria-invalid');
  }
  trigger.querySelector('.select-value')!.textContent = source.selectedOptions[0]?.text ?? 'No options available';
  menu.setAttribute('aria-label', name);
  menu.replaceChildren(...[...source.options].flatMap((option, index) => {
    if (option.hidden) return [];
    const button = document.createElement('button');
    button.type = 'button'; button.tabIndex = -1;
    button.setAttribute('role', 'option');
    button.setAttribute('aria-selected', String(index === source.selectedIndex));
    button.dataset.index = String(index);
    button.disabled = option.disabled || (option.parentElement instanceof HTMLOptGroupElement && option.parentElement.disabled);
    const text = document.createElement('span'); text.textContent = option.text;
    button.append(text);
    if (index === source.selectedIndex) {
      const check = document.createElement('span'); check.className = 'option-check';
      check.setAttribute('aria-hidden', 'true'); check.textContent = '✓'; button.append(check);
    }
    button.addEventListener('click', () => choose(view, button));
    return [button];
  }));
}

function enhance(source: HTMLSelectElement): SelectView {
  const wrapper = document.createElement('span'); wrapper.className = 'web-select custom-select';
  const trigger = document.createElement('button'); trigger.type = 'button'; trigger.className = 'select-trigger';
  trigger.setAttribute('role', 'combobox'); trigger.setAttribute('aria-haspopup', 'listbox'); trigger.setAttribute('aria-expanded', 'false');
  trigger.innerHTML = '<span class="select-value"></span><span class="select-chevron" aria-hidden="true"></span>';
  const menu = document.createElement('div'); menu.className = 'select-menu web-select-menu';
  menu.id = `web-select-menu-${++sequence}`; menu.setAttribute('role', 'listbox'); menu.hidden = true;
  if (typeof menu.showPopover === 'function') menu.setAttribute('popover', 'manual');
  trigger.setAttribute('aria-controls', menu.id);
  const error = document.createElement('span'); error.className = 'field-note web-select-error';
  error.id = `${menu.id}-error`; error.setAttribute('role', 'alert');
  source.before(wrapper); wrapper.append(source, trigger, menu, error);
  source.hidden = true; source.tabIndex = -1; source.setAttribute('aria-hidden', 'true');
  const view = {source, wrapper, trigger, menu, error, signature: ''};
  views.set(source, view);
  trigger.addEventListener('click', () => active === view ? close(true) : open(view));
  trigger.addEventListener('keydown', event => keydown(event, view));
  menu.addEventListener('keydown', event => keydown(event, view));
  source.addEventListener('invalid', event => {
    event.preventDefault(); trigger.setAttribute('aria-invalid', 'true'); trigger.focus();
    error.textContent = source.validationMessage;
  });
  source.addEventListener('change', () => update(view));
  return view;
}

export function syncWebSelects(root: HTMLElement): void {
  if (active && (!active.source.isConnected || active.source.disabled || active.source.parentElement?.closest('[hidden]') !== null)) close();
  root.querySelectorAll<HTMLSelectElement>('select').forEach(source => update(views.get(source) ?? enhance(source)));
}

export function installWebSelects(root: HTMLElement): void {
  syncWebSelects(root);
  let queued = false;
  new MutationObserver(() => {
    if (queued) return;
    queued = true;
    queueMicrotask(() => {queued = false; syncWebSelects(root);});
  }).observe(root, {subtree: true, childList: true, attributes: true, attributeFilter: ['disabled', 'required', 'selected', 'hidden', 'aria-describedby', 'aria-label', 'aria-labelledby', 'name']});
  document.addEventListener('pointerdown', event => {
    if (active && event.target instanceof Node && !active.wrapper.contains(event.target) && !active.menu.contains(event.target)) close();
  });
  document.addEventListener('close', () => close(), true);
  document.addEventListener('reset', () => requestAnimationFrame(() => syncWebSelects(root)), true);
  window.addEventListener('resize', () => {if (active) position(active);});
  document.addEventListener('scroll', event => {if (active && event.target !== active.menu) position(active);}, true);
}
