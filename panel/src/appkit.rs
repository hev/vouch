//! The panel window, in `AppKit`.
//!
//! A non-activating floating `NSPanel`: it can take Esc without pulling the
//! operator's terminal out of focus, it never hides when another app is
//! active, and it carries no Approve control. It runs in its own process
//! (`vouch-agent panel`), so the agent's request loop never shares a thread
//! with `AppKit`: the agent starts the process when the Touch ID permit is
//! taken and kills it when the sheet resolves. The process exits on its own
//! only when the operator denies ([`crate::EXIT_DENIED`]) or the request's
//! deadline passes ([`crate::EXIT_EXPIRED`]).
//!
//! The workspace denies `unsafe_code`; this module lifts it for the `AppKit`
//! calls objc2 marks unsafe (target/action, timers, class definition).
#![allow(unsafe_code)]

use std::cell::{Cell, OnceCell};

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject};
use objc2::{
    AllocAnyThread as _, DefinedClass as _, MainThreadMarker, MainThreadOnly, define_class,
    msg_send, sel,
};
use objc2_app_kit::{
    NSAppearance, NSAppearanceCustomization as _, NSAppearanceNameDarkAqua, NSApplication,
    NSApplicationActivationPolicy, NSBackingStoreType, NSButton, NSColor, NSControlSize, NSFont,
    NSFontAttributeName, NSFontWeightBold, NSFontWeightMedium, NSFontWeightRegular,
    NSFontWeightSemibold, NSForegroundColorAttributeName, NSLayoutAttribute, NSLineBreakMode,
    NSPanel, NSProgressIndicator, NSProgressIndicatorStyle, NSScreen, NSStackView,
    NSStackViewGravity, NSStatusWindowLevel, NSTextField, NSUserInterfaceLayoutOrientation, NSView,
    NSWindowCollectionBehavior, NSWindowStyleMask, NSWindowTitleVisibility,
};
use objc2_foundation::{
    NSAttributedStringKey, NSEdgeInsets, NSMutableAttributedString, NSPoint, NSRange, NSRect,
    NSSize, NSString, NSTimer,
};

use crate::{ChipTone, CodeKind, EXIT_DENIED, EXIT_EXPIRED, NO_REASON, PanelView, WHY_CAVEAT};

const WIDTH: f64 = 470.0;
const INSET: f64 = 16.0;
const INNER: f64 = WIDTH - 2.0 * INSET;
/// Roughly where the system Touch ID sheet's left edge falls, measured from
/// the centre of the screen. The panel sits just left of it.
const SHEET_HALF_WIDTH: f64 = 170.0;
const GAP: f64 = 22.0;

struct Palette;

impl Palette {
    fn rgba(red: u8, green: u8, blue: u8, alpha: f64) -> Retained<NSColor> {
        NSColor::colorWithSRGBRed_green_blue_alpha(
            f64::from(red) / 255.0,
            f64::from(green) / 255.0,
            f64::from(blue) / 255.0,
            alpha,
        )
    }
    fn ink() -> Retained<NSColor> {
        Self::rgba(0xf2, 0xf2, 0xf4, 1.0)
    }
    fn muted() -> Retained<NSColor> {
        Self::rgba(0x9b, 0x9b, 0xa3, 1.0)
    }
    fn line() -> Retained<NSColor> {
        Self::rgba(255, 255, 255, 0.09)
    }
    fn who() -> Retained<NSColor> {
        Self::rgba(0x8e, 0xca, 0xe6, 1.0)
    }
    fn why() -> Retained<NSColor> {
        Self::rgba(0xe9, 0xc4, 0x6a, 1.0)
    }
    fn what() -> Retained<NSColor> {
        Self::rgba(0xb5, 0xe4, 0x8c, 1.0)
    }
    fn danger() -> Retained<NSColor> {
        Self::rgba(0xff, 0x8a, 0x80, 1.0)
    }
    fn chip_text() -> Retained<NSColor> {
        Self::rgba(0xd6, 0xd6, 0xdc, 1.0)
    }
}

#[derive(Default)]
struct Ivars {
    issued_at: Cell<i64>,
    expires_at: Cell<i64>,
    timer_label: OnceCell<Retained<NSTextField>>,
    bar: OnceCell<Retained<NSProgressIndicator>>,
    env_list: OnceCell<Retained<NSStackView>>,
    env_button: OnceCell<Retained<NSButton>>,
    panel: OnceCell<Retained<NSPanel>>,
    root: OnceCell<Retained<NSStackView>>,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements, and this class does
    // not implement Drop.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "VouchPanelController"]
    #[ivars = Ivars]
    struct Controller;

    impl Controller {
        /// Esc or the Deny button. The agent reads the exit status and
        /// cancels the Touch ID attempt this panel belongs to.
        #[unsafe(method(deny:))]
        fn deny(&self, _sender: Option<&AnyObject>) {
            std::process::exit(EXIT_DENIED);
        }

        #[unsafe(method(toggleEnv:))]
        fn toggle_env(&self, _sender: Option<&AnyObject>) {
            let ivars = self.ivars();
            let (Some(list), Some(button)) = (ivars.env_list.get(), ivars.env_button.get()) else {
                return;
            };
            let show = list.isHidden();
            list.setHidden(!show);
            button.setTitle(&NSString::from_str(if show { "hide" } else { "show" }));
            self.fit();
        }

        #[unsafe(method(tick:))]
        fn tick(&self, _timer: Option<&AnyObject>) {
            self.refresh_countdown();
        }
    }
);

impl Controller {
    fn new(mtm: MainThreadMarker, view: &PanelView) -> Retained<Self> {
        let ivars = Ivars::default();
        ivars.issued_at.set(view.issued_at);
        ivars.expires_at.set(view.expires_at);
        let this = Self::alloc(mtm).set_ivars(ivars);
        // SAFETY: NSObject's designated initializer.
        unsafe { msg_send![super(this), init] }
    }

    fn refresh_countdown(&self) {
        let ivars = self.ivars();
        let now = now();
        let expires_at = ivars.expires_at.get();
        if now >= expires_at {
            // The request is dead; the hook has already failed closed.
            std::process::exit(EXIT_EXPIRED);
        }
        let shape = PanelView {
            kind: String::new(),
            issued_at: ivars.issued_at.get(),
            expires_at,
            who: crate::Who {
                session: String::new(),
                chips: vec![],
            },
            why: None,
            what: crate::What {
                heading: String::new(),
                badge: None,
                command: None,
                code: vec![],
                rows: vec![],
                env: vec![],
                note: None,
            },
        };
        if let Some(label) = ivars.timer_label.get() {
            label.setStringValue(&NSString::from_str(&shape.countdown(now)));
        }
        if let Some(bar) = ivars.bar.get() {
            bar.setDoubleValue(shape.remaining_fraction(now) * 100.0);
        }
    }

    /// Resizes the panel to its content, keeping its top edge where it was.
    fn fit(&self) {
        let ivars = self.ivars();
        let (Some(panel), Some(root)) = (ivars.panel.get(), ivars.root.get()) else {
            return;
        };
        root.layoutSubtreeIfNeeded();
        let size = root.fittingSize();
        let frame = panel.frame();
        let top = frame.origin.y + frame.size.height;
        let content = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(WIDTH, size.height));
        let mut next = panel.frameRectForContentRect(content);
        next.origin.x = frame.origin.x;
        next.origin.y = top - next.size.height;
        panel.setFrame_display(next, true);
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

fn label(
    mtm: MainThreadMarker,
    text: &str,
    size: f64,
    weight: f64,
    color: &NSColor,
) -> Retained<NSTextField> {
    let field = NSTextField::labelWithString(&NSString::from_str(text), mtm);
    field.setFont(Some(&NSFont::systemFontOfSize_weight(size, weight)));
    field.setTextColor(Some(color));
    field
}

fn wrapping(
    mtm: MainThreadMarker,
    text: &str,
    size: f64,
    color: &NSColor,
    width: f64,
) -> Retained<NSTextField> {
    let field = NSTextField::wrappingLabelWithString(&NSString::from_str(text), mtm);
    // SAFETY: a system weight constant.
    field.setFont(Some(&NSFont::systemFontOfSize_weight(size, unsafe {
        NSFontWeightRegular
    })));
    field.setTextColor(Some(color));
    field.setSelectable(false);
    field.setPreferredMaxLayoutWidth(width);
    pin_width(&field, width);
    field
}

fn mono(size: f64, weight: f64) -> Retained<NSFont> {
    NSFont::monospacedSystemFontOfSize_weight(size, weight)
}

fn pin_width(view: &NSView, width: f64) {
    view.widthAnchor()
        .constraintEqualToConstant(width)
        .setActive(true);
}

fn stack(mtm: MainThreadMarker, vertical: bool, spacing: f64) -> Retained<NSStackView> {
    let stack = NSStackView::new(mtm);
    stack.setOrientation(if vertical {
        NSUserInterfaceLayoutOrientation::Vertical
    } else {
        NSUserInterfaceLayoutOrientation::Horizontal
    });
    stack.setAlignment(if vertical {
        NSLayoutAttribute::Leading
    } else {
        NSLayoutAttribute::CenterY
    });
    stack.setSpacing(spacing);
    stack
}

/// Gives `view` a layer-backed fill and corner radius.
fn paint(view: &NSView, fill: &NSColor, radius: f64) {
    view.setWantsLayer(true);
    if let Some(layer) = view.layer() {
        layer.setBackgroundColor(Some(&fill.CGColor()));
        layer.setCornerRadius(radius);
    }
}

/// `content` inside a filled, rounded container with the given margins.
fn filled_box(
    mtm: MainThreadMarker,
    fill: &NSColor,
    radius: f64,
    margins: NSSize,
    content: &NSView,
) -> Retained<NSStackView> {
    let frame = stack(mtm, false, 0.0);
    frame.setEdgeInsets(NSEdgeInsets {
        top: margins.height,
        left: margins.width,
        bottom: margins.height,
        right: margins.width,
    });
    frame.addArrangedSubview(content);
    paint(&frame, fill, radius);
    frame
}

/// A filled rectangle of a fixed width; height comes from constraints.
fn bar_view(mtm: MainThreadMarker, fill: &NSColor, width: f64) -> Retained<NSView> {
    let view = NSView::new(mtm);
    view.setTranslatesAutoresizingMaskIntoConstraints(false);
    paint(&view, fill, 0.0);
    pin_width(&view, width);
    view
}

fn separator(mtm: MainThreadMarker) -> Retained<NSView> {
    let line = bar_view(mtm, &Palette::line(), WIDTH);
    line.heightAnchor()
        .constraintEqualToConstant(1.0)
        .setActive(true);
    line
}

fn section(mtm: MainThreadMarker) -> Retained<NSStackView> {
    let section = stack(mtm, true, 6.0);
    section.setEdgeInsets(NSEdgeInsets {
        top: 14.0,
        left: INSET,
        bottom: 14.0,
        right: INSET,
    });
    pin_width(&section, WIDTH);
    section
}

/// The small caps label that opens a section, with an optional caveat.
fn section_label(
    mtm: MainThreadMarker,
    title: &str,
    color: &NSColor,
    caveat: Option<&str>,
) -> Retained<NSStackView> {
    let row = stack(mtm, false, 8.0);
    // SAFETY: system weight constants.
    let (bold, medium) = unsafe { (NSFontWeightBold, NSFontWeightMedium) };
    row.addArrangedSubview(&label(mtm, &title.to_uppercase(), 10.5, bold, color));
    if let Some(caveat) = caveat {
        row.addArrangedSubview(&label(mtm, caveat, 11.0, medium, &Palette::muted()));
    }
    row
}

fn colored(
    text: &str,
    font: &NSFont,
    runs: &[(usize, usize, Retained<NSColor>)],
) -> Retained<NSMutableAttributedString> {
    let string = NSMutableAttributedString::initWithString(
        NSMutableAttributedString::alloc(),
        &NSString::from_str(text),
    );
    let whole = NSRange::new(0, NSString::from_str(text).length());
    // SAFETY: the attribute keys are AppKit's, and each value has the type
    // its key requires (NSFont for the font, NSColor for the colour).
    unsafe {
        string.addAttribute_value_range(attribute(NSFontAttributeName), font, whole);
        string.addAttribute_value_range(
            attribute(NSForegroundColorAttributeName),
            &Palette::ink(),
            whole,
        );
        for (start, length, color) in runs {
            string.addAttribute_value_range(
                attribute(NSForegroundColorAttributeName),
                color,
                NSRange::new(*start, *length),
            );
        }
    }
    string
}

fn attribute(key: &'static NSAttributedStringKey) -> &'static NSAttributedStringKey {
    key
}

/// UTF-16 length, the unit `NSRange` counts in.
fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

fn code_block(
    mtm: MainThreadMarker,
    text: &NSMutableAttributedString,
    wrap: bool,
) -> Retained<NSStackView> {
    let field = if wrap {
        let field = NSTextField::wrappingLabelWithString(&NSString::from_str(""), mtm);
        field.setPreferredMaxLayoutWidth(INNER - 24.0);
        field
    } else {
        let field = NSTextField::labelWithString(&NSString::from_str(""), mtm);
        field.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
        field
    };
    field.setAttributedStringValue(text);
    field.setSelectable(false);
    pin_width(&field, INNER - 24.0);
    let block = filled_box(
        mtm,
        &Palette::rgba(0, 0, 0, 0.35),
        8.0,
        NSSize::new(12.0, 10.0),
        &field,
    );
    pin_width(&block, INNER);
    block
}

fn chip(mtm: MainThreadMarker, text: &str, tone: ChipTone) -> Retained<NSStackView> {
    let (fill, ink) = match tone {
        ChipTone::Context => (Palette::rgba(0x8e, 0xca, 0xe6, 0.18), Palette::who()),
        ChipTone::Plain => (Palette::rgba(255, 255, 255, 0.08), Palette::chip_text()),
        ChipTone::Remote => (Palette::rgba(0xff, 0x8a, 0x80, 0.18), Palette::danger()),
    };
    // SAFETY: a system weight constant.
    let text = label(mtm, text, 11.5, unsafe { NSFontWeightRegular }, &ink);
    filled_box(mtm, &fill, 9.0, NSSize::new(8.0, 2.0), &text)
}

#[allow(clippy::too_many_lines)] // one function, read top to bottom like the panel
fn build(
    mtm: MainThreadMarker,
    view: &PanelView,
    controller: &Controller,
) -> Retained<NSStackView> {
    // SAFETY: system weight constants.
    let (regular, medium, semibold, bold) = unsafe {
        (
            NSFontWeightRegular,
            NSFontWeightMedium,
            NSFontWeightSemibold,
            NSFontWeightBold,
        )
    };
    let root = stack(mtm, true, 0.0);
    pin_width(&root, WIDTH);

    // Header: mark, kind, countdown.
    let header = stack(mtm, false, 10.0);
    header.setEdgeInsets(NSEdgeInsets {
        top: 12.0,
        left: INSET,
        bottom: 12.0,
        right: INSET,
    });
    pin_width(&header, WIDTH);
    header.addView_inGravity(
        &label(mtm, "vouch", 13.0, bold, &Palette::ink()),
        NSStackViewGravity::Leading,
    );
    header.addView_inGravity(
        &label(mtm, &view.kind, 12.0, regular, &Palette::muted()),
        NSStackViewGravity::Leading,
    );
    let timer = label(mtm, &view.countdown(now()), 12.0, medium, &Palette::muted());
    timer.setFont(Some(&mono(12.0, medium)));
    header.addView_inGravity(&timer, NSStackViewGravity::Trailing);
    let bar = NSProgressIndicator::new(mtm);
    bar.setStyle(NSProgressIndicatorStyle::Bar);
    bar.setIndeterminate(false);
    bar.setControlSize(NSControlSize::Small);
    bar.setMinValue(0.0);
    bar.setMaxValue(100.0);
    bar.setDoubleValue(view.remaining_fraction(now()) * 100.0);
    pin_width(&bar, 64.0);
    header.addView_inGravity(&bar, NSStackViewGravity::Trailing);
    root.addArrangedSubview(&header);
    root.addArrangedSubview(&separator(mtm));
    let _ = controller.ivars().timer_label.set(timer);
    let _ = controller.ivars().bar.set(bar);

    // Who's asking.
    let who = section(mtm);
    who.addArrangedSubview(&section_label(mtm, "Who's asking", &Palette::who(), None));
    let session = label(mtm, &view.who.session, 22.0, semibold, &Palette::ink());
    session.setLineBreakMode(NSLineBreakMode::ByTruncatingMiddle);
    session
        .widthAnchor()
        .constraintLessThanOrEqualToConstant(INNER)
        .setActive(true);
    who.addArrangedSubview(&session);
    if !view.who.chips.is_empty() {
        let chips = stack(mtm, false, 6.0);
        for item in &view.who.chips {
            chips.addArrangedSubview(&chip(mtm, &item.text, item.tone));
        }
        who.addArrangedSubview(&chips);
    }
    root.addArrangedSubview(&who);
    root.addArrangedSubview(&separator(mtm));

    // Why.
    let why = section(mtm);
    if let Some(reason) = &view.why {
        why.addArrangedSubview(&section_label(
            mtm,
            "Why",
            &Palette::why(),
            Some(WHY_CAVEAT),
        ));
        let quote = stack(mtm, false, 10.0);
        quote.setAlignment(NSLayoutAttribute::Top);
        let text = wrapping(mtm, reason, 15.0, &Palette::ink(), INNER - 13.0);
        let rule = bar_view(mtm, &Palette::why(), 3.0);
        quote.addArrangedSubview(&rule);
        quote.addArrangedSubview(&text);
        rule.heightAnchor()
            .constraintEqualToAnchor(&text.heightAnchor())
            .setActive(true);
        why.addArrangedSubview(&quote);
    } else {
        why.addArrangedSubview(&section_label(mtm, "Why", &Palette::why(), None));
        let missing = label(mtm, NO_REASON, 13.0, regular, &Palette::muted());
        missing.setFont(Some(&NSFont::systemFontOfSize_weight(13.0, regular)));
        why.addArrangedSubview(&missing);
    }
    root.addArrangedSubview(&why);
    root.addArrangedSubview(&separator(mtm));

    // What will run.
    let what = section(mtm);
    what.addArrangedSubview(&section_label(
        mtm,
        &view.what.heading,
        &Palette::what(),
        view.what.badge.as_deref(),
    ));
    if let Some(command) = &view.what.command {
        let verb = if command.verb.is_empty() {
            String::new()
        } else {
            format!("{} ", command.verb)
        };
        let text = format!("{}{verb}{}", command.prompt, command.rest);
        let prompt_len = utf16_len(&command.prompt);
        let runs = vec![
            (0, prompt_len, Palette::muted()),
            (prompt_len, utf16_len(&command.verb), Palette::danger()),
        ];
        what.addArrangedSubview(&code_block(
            mtm,
            &colored(&text, &mono(13.0, regular), &runs),
            true,
        ));
    }
    if !view.what.code.is_empty() {
        let mut text = String::new();
        let mut runs = Vec::new();
        for (index, line) in view.what.code.iter().enumerate() {
            if index > 0 {
                text.push('\n');
            }
            let start = utf16_len(&text);
            text.push_str(&line.text);
            let color = match line.kind {
                CodeKind::Plain => Palette::ink(),
                CodeKind::Added => Palette::what(),
                CodeKind::Removed => Palette::danger(),
                CodeKind::Context => Palette::muted(),
            };
            runs.push((start, utf16_len(&line.text), color));
        }
        let wrap = view.what.code.len() == 1;
        what.addArrangedSubview(&code_block(
            mtm,
            &colored(&text, &mono(12.0, regular), &runs),
            wrap,
        ));
    }
    let rows = stack(mtm, true, 3.0);
    let mut has_rows = false;
    for (name, value) in &view.what.rows {
        rows.addArrangedSubview(&kv_row(mtm, name, value, None));
        has_rows = true;
    }
    if let Some(summary) = view.env_summary() {
        let button = NSButton::new(mtm);
        button.setTitle(&NSString::from_str("show"));
        button.setBordered(false);
        button.setFont(Some(&NSFont::systemFontOfSize_weight(12.0, regular)));
        button.setContentTintColor(Some(&Palette::muted()));
        // SAFETY: the controller outlives the panel (both live until exit),
        // and `toggleEnv:` takes one object argument.
        unsafe {
            button.setTarget(Some(controller));
            button.setAction(Some(sel!(toggleEnv:)));
        }
        rows.addArrangedSubview(&kv_row(
            mtm,
            "env",
            &format!("{summary} kept ·"),
            Some(&button),
        ));
        let list = stack(mtm, true, 1.0);
        list.setEdgeInsets(NSEdgeInsets {
            top: 0.0,
            left: 84.0,
            bottom: 0.0,
            right: 0.0,
        });
        for entry in &view.what.env {
            let line = label(mtm, entry, 11.5, regular, &Palette::chip_text());
            line.setFont(Some(&mono(11.5, regular)));
            line.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
            line.widthAnchor()
                .constraintLessThanOrEqualToConstant(INNER - 84.0)
                .setActive(true);
            list.addArrangedSubview(&line);
        }
        list.setHidden(true);
        rows.addArrangedSubview(&list);
        let _ = controller.ivars().env_list.set(list);
        let _ = controller.ivars().env_button.set(button);
        has_rows = true;
    }
    if has_rows {
        what.setCustomSpacing_afterView(
            10.0,
            &what.arrangedSubviews().lastObject().expect("block"),
        );
        what.addArrangedSubview(&rows);
    }
    if let Some(note) = &view.what.note {
        what.addArrangedSubview(&wrapping(mtm, note, 11.5, &Palette::muted(), INNER));
    }
    root.addArrangedSubview(&what);

    // Footer: Touch ID approves; Esc or Deny cancels. No Approve button.
    let footer = stack(mtm, false, 10.0);
    footer.setEdgeInsets(NSEdgeInsets {
        top: 9.0,
        left: INSET,
        bottom: 9.0,
        right: INSET - 6.0,
    });
    footer.addView_inGravity(
        &label(
            mtm,
            "☝︎ Touch ID to approve",
            12.0,
            semibold,
            &Palette::ink(),
        ),
        NSStackViewGravity::Leading,
    );
    // SAFETY: the controller outlives the panel, and `deny:` takes one
    // object argument.
    let deny = unsafe {
        NSButton::buttonWithTitle_target_action(
            &NSString::from_str("esc  Deny"),
            Some(controller),
            Some(sel!(deny:)),
            mtm,
        )
    };
    deny.setKeyEquivalent(&NSString::from_str("\u{1b}"));
    deny.setControlSize(NSControlSize::Small);
    footer.addView_inGravity(&deny, NSStackViewGravity::Trailing);
    let footer_box = filled_box(
        mtm,
        &Palette::rgba(0, 0, 0, 0.22),
        0.0,
        NSSize::new(0.0, 0.0),
        &footer,
    );
    pin_width(&footer_box, WIDTH);
    pin_width(&footer, WIDTH);
    root.addArrangedSubview(&footer_box);
    root
}

fn kv_row(
    mtm: MainThreadMarker,
    name: &str,
    value: &str,
    extra: Option<&NSButton>,
) -> Retained<NSStackView> {
    // SAFETY: a system weight constant.
    let regular = unsafe { NSFontWeightRegular };
    let row = stack(mtm, false, 10.0);
    row.setAlignment(NSLayoutAttribute::FirstBaseline);
    let key = label(mtm, name, 12.0, regular, &Palette::muted());
    pin_width(&key, 74.0);
    row.addArrangedSubview(&key);
    let value_width = if extra.is_some() {
        INNER - 84.0 - 50.0
    } else {
        INNER - 84.0
    };
    let shown = NSTextField::wrappingLabelWithString(&NSString::from_str(value), mtm);
    shown.setFont(Some(&mono(11.5, regular)));
    shown.setTextColor(Some(&Palette::ink()));
    shown.setSelectable(false);
    shown.setPreferredMaxLayoutWidth(value_width);
    if extra.is_some() {
        shown
            .widthAnchor()
            .constraintLessThanOrEqualToConstant(value_width)
            .setActive(true);
    } else {
        pin_width(&shown, value_width);
    }
    row.addArrangedSubview(&shown);
    if let Some(button) = extra {
        row.addArrangedSubview(button);
    }
    row
}

/// Shows `view` until the operator denies (the process exits with
/// [`EXIT_DENIED`]), the deadline passes ([`EXIT_EXPIRED`]), or the agent
/// kills the process. Must be called on the main thread of a process with a
/// window server connection; returns an error otherwise.
pub fn run_panel(view: &PanelView) -> Result<(), &'static str> {
    let mtm = MainThreadMarker::new().ok_or("the panel must run on the main thread")?;
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);

    let controller = Controller::new(mtm, view);
    let root = build(mtm, view, &controller);

    let style = NSWindowStyleMask::Titled
        | NSWindowStyleMask::NonactivatingPanel
        | NSWindowStyleMask::FullSizeContentView;
    // SAFETY: a fresh panel with a valid frame; `setReleasedWhenClosed` is
    // turned off below because Rust owns the reference.
    let panel = {
        NSPanel::initWithContentRect_styleMask_backing_defer(
            NSPanel::alloc(mtm),
            NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(WIDTH, 400.0)),
            style,
            NSBackingStoreType::Buffered,
            false,
        )
    };
    // SAFETY: Rust holds the only reference that should free it.
    unsafe { panel.setReleasedWhenClosed(false) };
    panel.setTitle(&NSString::from_str("vouch"));
    panel.setTitleVisibility(NSWindowTitleVisibility::Hidden);
    panel.setTitlebarAppearsTransparent(true);
    panel.setMovableByWindowBackground(true);
    panel.setFloatingPanel(true);
    panel.setHidesOnDeactivate(false);
    panel.setBecomesKeyOnlyIfNeeded(false);
    panel.setLevel(NSStatusWindowLevel);
    panel.setCollectionBehavior(
        NSWindowCollectionBehavior::CanJoinAllSpaces
            | NSWindowCollectionBehavior::FullScreenAuxiliary,
    );
    for button in [
        objc2_app_kit::NSWindowButton::CloseButton,
        objc2_app_kit::NSWindowButton::MiniaturizeButton,
        objc2_app_kit::NSWindowButton::ZoomButton,
    ] {
        if let Some(control) = panel.standardWindowButton(button) {
            control.setHidden(true);
        }
    }
    if let Some(dark) = NSAppearance::appearanceNamed(unsafe { NSAppearanceNameDarkAqua }) {
        panel.setAppearance(Some(&dark));
    }

    panel.setBackgroundColor(Some(&Palette::rgba(32, 32, 36, 0.97)));
    let backdrop = NSView::new(mtm);
    backdrop.addSubview(&root);
    root.setTranslatesAutoresizingMaskIntoConstraints(false);
    root.topAnchor()
        .constraintEqualToAnchor(&backdrop.topAnchor())
        .setActive(true);
    root.leadingAnchor()
        .constraintEqualToAnchor(&backdrop.leadingAnchor())
        .setActive(true);
    panel.setContentView(Some(&backdrop));

    let _ = controller.ivars().panel.set(panel.clone());
    let _ = controller.ivars().root.set(root.clone());
    controller.fit();
    place(mtm, &panel);
    controller.refresh_countdown();

    // SAFETY: `tick:` takes the timer as its one argument, and the
    // controller lives for the rest of the process.
    let _timer = unsafe {
        NSTimer::scheduledTimerWithTimeInterval_target_selector_userInfo_repeats(
            0.5,
            &controller,
            sel!(tick:),
            None,
            true,
        )
    };
    panel.makeKeyAndOrderFront(None);
    panel.orderFrontRegardless();
    app.run();
    Ok(())
}

/// Just left of the system sheet, which macOS centres on the main screen.
fn place(mtm: MainThreadMarker, panel: &NSPanel) {
    let Some(screen) = NSScreen::mainScreen(mtm) else {
        panel.center();
        return;
    };
    let visible = screen.visibleFrame();
    let size = panel.frame().size;
    let mid_x = visible.origin.x + visible.size.width / 2.0;
    let mid_y = visible.origin.y + visible.size.height / 2.0;
    let mut x = mid_x - SHEET_HALF_WIDTH - GAP - size.width;
    if x < visible.origin.x + 8.0 {
        x = visible.origin.x + 8.0;
    }
    let y = (mid_y - size.height / 2.0).max(visible.origin.y + 8.0);
    panel.setFrameOrigin(NSPoint::new(x, y));
}
