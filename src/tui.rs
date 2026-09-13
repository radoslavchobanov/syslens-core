//! Human-facing terminal monitor for SysLens Core.
//!
//! The collector keeps its stable JSON/MQTT contract. This module only turns
//! the same local snapshot into a readable interactive view.

use crate::{SnapshotArgs, TuiArgs};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Tabs, Wrap},
};
use serde_json::Value;
use std::{
    cmp::Ordering,
    collections::VecDeque,
    io::{self, stdout},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const HISTORY_LIMIT: usize = 42;
const CYAN: Color = Color::Cyan;
const MUTED: Color = Color::DarkGray;
const GREEN: Color = Color::Green;
const AMBER: Color = Color::Yellow;
const RED: Color = Color::LightRed;
const PURPLE: Color = Color::Magenta;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Overview,
    Processes,
    Thermals,
}

impl Screen {
    fn index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::Processes => 1,
            Self::Thermals => 2,
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Overview => Self::Processes,
            Self::Processes => Self::Thermals,
            Self::Thermals => Self::Overview,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessSort {
    Cpu,
    Memory,
}

struct App {
    snapshot: Value,
    screen: Screen,
    process_sort: ProcessSort,
    selected_process: usize,
    cpu_history: VecDeque<f64>,
    memory_history: VecDeque<f64>,
    down_history: VecDeque<f64>,
    up_history: VecDeque<f64>,
    refresh_interval: Duration,
    refreshed_at: Instant,
}

impl App {
    fn new(snapshot: Value, refresh_interval: Duration) -> Self {
        let mut app = Self {
            snapshot: Value::Null,
            screen: Screen::Overview,
            process_sort: ProcessSort::Cpu,
            selected_process: 0,
            cpu_history: VecDeque::with_capacity(HISTORY_LIMIT),
            memory_history: VecDeque::with_capacity(HISTORY_LIMIT),
            down_history: VecDeque::with_capacity(HISTORY_LIMIT),
            up_history: VecDeque::with_capacity(HISTORY_LIMIT),
            refresh_interval,
            refreshed_at: Instant::now(),
        };
        app.update(snapshot);
        app
    }

    fn update(&mut self, snapshot: Value) {
        push_history(
            &mut self.cpu_history,
            number(&snapshot, "/cpu/usage_percent"),
        );
        push_history(
            &mut self.memory_history,
            number(&snapshot, "/memory/usage_percent"),
        );
        push_history(
            &mut self.down_history,
            number(&snapshot, "/network/download_bytes_per_sec"),
        );
        push_history(
            &mut self.up_history,
            number(&snapshot, "/network/upload_bytes_per_sec"),
        );
        self.snapshot = snapshot;
        self.refreshed_at = Instant::now();
        self.selected_process = self
            .selected_process
            .min(self.processes().len().saturating_sub(1));
    }

    fn processes(&self) -> Vec<&Value> {
        let mut processes: Vec<&Value> = self
            .snapshot
            .pointer("/processes/top")
            .and_then(Value::as_array)
            .map(|items| items.iter().collect())
            .unwrap_or_default();
        processes.sort_by(|left, right| {
            let metric = match self.process_sort {
                ProcessSort::Cpu => "cpu_average_percent",
                ProcessSort::Memory => "private_bytes",
            };
            number_at(right, metric)
                .partial_cmp(&number_at(left, metric))
                .unwrap_or(Ordering::Equal)
        });
        processes
    }
}

pub(crate) fn run(args: TuiArgs) -> Result<(), String> {
    if !args.interval.is_finite() || args.interval < 0.5 {
        return Err("tui interval must be at least 0.5 seconds".into());
    }
    let interval = Duration::try_from_secs_f64(args.interval).map_err(|error| error.to_string())?;
    crate::collector::validate_window(args.snapshot.sample_window)?;
    let worker = SamplingWorker::start(args.snapshot);
    worker.request();
    let mut app = App::new(Value::Null, interval);

    enable_raw_mode().map_err(|error| error.to_string())?;
    let _guard = TerminalGuard;
    let mut output = stdout();
    execute!(output, EnterAlternateScreen).map_err(|error| error.to_string())?;
    let backend = CrosstermBackend::new(output);
    let mut terminal = Terminal::new(backend).map_err(|error| error.to_string())?;

    run_loop(&mut terminal, &mut app, &worker)
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
    }
}

// One in-flight request and one replaceable result keep work and memory bounded.
// Drop disconnects requests and joins the worker, including all error exits.
struct SamplingWorker {
    requests: Option<mpsc::SyncSender<()>>,
    busy: Arc<AtomicBool>,
    latest: Arc<Mutex<Option<Result<Value, String>>>>,
    join: Option<thread::JoinHandle<()>>,
}

impl SamplingWorker {
    fn start(mut args: SnapshotArgs) -> Self {
        args.process_limit = usize::MAX;
        let mut collector = crate::collector::Collector::default();
        let mut state = crate::CollectorState::default();
        Self::spawn(move || local_snapshot(&args, &mut state, &mut collector))
    }

    fn spawn(mut sample: impl FnMut() -> Result<Value, String> + Send + 'static) -> Self {
        let (tx, rx) = mpsc::sync_channel(1);
        let busy = Arc::new(AtomicBool::new(false));
        let latest = Arc::new(Mutex::new(None));
        let worker_busy = Arc::clone(&busy);
        let worker_latest = Arc::clone(&latest);
        let join = thread::spawn(move || {
            while rx.recv().is_ok() {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(&mut sample))
                    .unwrap_or_else(|_| Err("sampling worker panicked".into()));
                let failed = result.is_err();
                *worker_latest
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Some(result);
                worker_busy.store(false, AtomicOrdering::Release);
                if failed {
                    break;
                }
            }
        });
        Self {
            requests: Some(tx),
            busy,
            latest,
            join: Some(join),
        }
    }

    fn request(&self) {
        if !self.busy.swap(true, AtomicOrdering::AcqRel)
            && self
                .requests
                .as_ref()
                .is_some_and(|requests| requests.try_send(()).is_err())
        {
            self.busy.store(false, AtomicOrdering::Release);
        }
    }

    fn take(&self) -> Option<Result<Value, String>> {
        self.latest
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    }
}

impl Drop for SamplingWorker {
    fn drop(&mut self) {
        self.requests.take();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

// Release ownership after each refresh so a TUI does not monopolize history.
// If an agent owns it, retain the TUI's ephemeral state without saving it.
fn local_snapshot(
    args: &SnapshotArgs,
    state: &mut crate::CollectorState,
    collector: &mut crate::collector::Collector,
) -> Result<Value, String> {
    let mut history =
        crate::history::HistoryStore::open(crate::state_path(), crate::history::Access::Local)?;
    if history.is_writer() {
        let data = collector.sample(args, &mut history.state);
        history.save()?;
        *state = history.state;
        Ok(data)
    } else {
        if state.metrics.is_empty() {
            *state = history.state;
        }
        Ok(collector.sample(args, state))
    }
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    worker: &SamplingWorker,
) -> Result<(), String> {
    let mut next_refresh = Instant::now() + app.refresh_interval;
    loop {
        if let Some(result) = worker.take() {
            app.update(result?);
        }
        terminal
            .draw(|frame| draw(frame, app))
            .map_err(|error| error.to_string())?;

        let wait = next_refresh
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(100));
        if event::poll(wait).map_err(|error| error.to_string())?
            && let Event::Key(key) = event::read().map_err(|error| error.to_string())?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Tab => app.screen = app.screen.next(),
                KeyCode::Char('1') => app.screen = Screen::Overview,
                KeyCode::Char('2') => app.screen = Screen::Processes,
                KeyCode::Char('3') => app.screen = Screen::Thermals,
                KeyCode::Char('c') => app.process_sort = ProcessSort::Cpu,
                KeyCode::Char('m') => app.process_sort = ProcessSort::Memory,
                KeyCode::Down | KeyCode::Char('j') => {
                    app.selected_process =
                        (app.selected_process + 1).min(app.processes().len().saturating_sub(1));
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    app.selected_process = app.selected_process.saturating_sub(1);
                }
                KeyCode::Char('r') => worker.request(),
                _ => {}
            }
        }

        if Instant::now() >= next_refresh {
            worker.request();
            next_refresh =
                crate::collector::next_deadline(next_refresh, Instant::now(), app.refresh_interval);
        }
    }
}

fn draw(frame: &mut ratatui::Frame, app: &App) {
    let area = frame.area();
    if area.width < 62 || area.height < 22 {
        let message = Paragraph::new("SysLens needs at least 62 × 22 terminal cells. Resize the terminal, then press q to quit.")
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title(" SysLens "));
        frame.render_widget(message, area);
        return;
    }

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(2),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(area);
    draw_header(frame, app, layout[0]);
    draw_tabs(frame, app, layout[1]);
    match app.screen {
        Screen::Overview => draw_overview(frame, app, layout[2]),
        Screen::Processes => draw_processes(frame, app, layout[2]),
        Screen::Thermals => draw_thermals(frame, app, layout[2]),
    }
    let keys = match app.screen {
        Screen::Overview => "Tab / 1–3 switch view   r refresh   q quit",
        Screen::Processes => "c CPU sort   m memory sort   j/k select   Tab switch view   q quit",
        Screen::Thermals => "Tab / 1–3 switch view   r refresh   q quit",
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(keys, Style::default().fg(MUTED))))
            .alignment(Alignment::Center),
        layout[3],
    );
}

fn draw_header(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let hostname = string(&app.snapshot, "/uptime/hostname", "localhost");
    let os = string(&app.snapshot, "/uptime/os", "Linux");
    let kernel = string(&app.snapshot, "/uptime/kernel", "kernel unknown");
    let uptime = duration(number(&app.snapshot, "/uptime/seconds"));
    let lines = vec![
        Line::from(vec![
            Span::styled(
                " SYSLENS ",
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                hostname,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                "LIVE",
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!(" {os} · {kernel} · up {uptime}"),
                Style::default().fg(MUTED),
            ),
            Span::styled(
                format!(" · refresh {}s", app.refresh_interval.as_secs_f32()),
                Style::default().fg(MUTED),
            ),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn draw_tabs(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let titles = [" 1 Overview ", " 2 Processes ", " 3 Thermals & inventory "]
        .iter()
        .map(|title| Line::from(*title))
        .collect::<Vec<_>>();
    frame.render_widget(
        Tabs::new(titles)
            .select(app.screen.index())
            .highlight_style(Style::default().fg(CYAN).add_modifier(Modifier::BOLD))
            .style(Style::default().fg(MUTED))
            .divider("│"),
        area,
    );
}

fn draw_overview(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let wide = area.width >= 118;
    let compact = !wide && area.height < 23;
    let rows = if wide {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(9), Constraint::Min(8)])
            .split(area)
    } else if compact {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(7), Constraint::Min(8)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Min(8),
            ])
            .split(area)
    };
    let cards = if wide || compact {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints(vec![Constraint::Ratio(1, 4); 4])
            .split(rows[0])
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints(vec![Constraint::Ratio(1, 2); 2])
            .split(rows[0])
    };
    draw_cpu_card(frame, app, cards[0], compact);
    draw_ram_card(frame, app, cards[1], compact);
    if wide || compact {
        draw_disk_card(frame, app, cards[2], compact);
        draw_gpu_card(frame, app, cards[3], compact);
    } else {
        let cards = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(vec![Constraint::Ratio(1, 2); 2])
            .split(rows[1]);
        draw_disk_card(frame, app, cards[0], false);
        draw_gpu_card(frame, app, cards[1], false);
    }
    draw_network_and_processes(frame, app, if wide || compact { rows[1] } else { rows[2] });
}

fn draw_cpu_card(frame: &mut ratatui::Frame, app: &App, area: Rect, compact: bool) {
    let cpu = app.snapshot.get("cpu").unwrap_or(&Value::Null);
    let thermal = number(&app.snapshot, "/temperature/cpu_current_celsius");
    let lines = if compact {
        vec![
            metric_line("Usage", percent(number_at(cpu, "usage_percent")), CYAN),
            metric_line("Temp", celsius(thermal), thermal_color(thermal)),
            metric_line("Power", watts(number_at(cpu, "power_watts")), AMBER),
        ]
    } else {
        vec![
            metric_line("Usage", percent(number_at(cpu, "usage_percent")), CYAN),
            metric_line("Temperature", celsius(thermal), thermal_color(thermal)),
            metric_line("Power", watts(number_at(cpu, "power_watts")), AMBER),
            text_line(
                "Mode",
                string_at(cpu, "/cpufreq/governors/0", "Not exposed"),
            ),
            text_line("Clock", mhz(number_at(cpu, "current_mhz_avg"))),
        ]
    };
    frame.render_widget(panel(" CPU ", CYAN, lines), area);
}

fn draw_ram_card(frame: &mut ratatui::Frame, app: &App, area: Rect, compact: bool) {
    let memory = app.snapshot.get("memory").unwrap_or(&Value::Null);
    let swap = memory.get("swap").unwrap_or(&Value::Null);
    let lines = if compact {
        vec![
            metric_line("RAM", percent(number_at(memory, "usage_percent")), GREEN),
            compact_text_line("Used", compact_used_total(memory)),
            metric_line(
                "Swap",
                percent(number_at(swap, "usage_percent")),
                Color::LightBlue,
            ),
        ]
    } else {
        vec![
            metric_line("RAM", percent(number_at(memory, "usage_percent")), GREEN),
            text_line("Used", used_total(memory)),
            metric_line(
                "Swap",
                percent(number_at(swap, "usage_percent")),
                Color::LightBlue,
            ),
            text_line("Swap used", used_total(swap)),
            text_line("Available", bytes(number_at(memory, "available_bytes"))),
        ]
    };
    frame.render_widget(panel(" RAM ", GREEN, lines), area);
}

fn draw_disk_card(frame: &mut ratatui::Frame, app: &App, area: Rect, compact: bool) {
    let disk = app.snapshot.get("disk").unwrap_or(&Value::Null);
    let root = disk.get("root").unwrap_or(&Value::Null);
    let temp = number(
        &app.snapshot,
        "/temperature/hardware/storage/current_celsius",
    );
    let lines = if compact {
        vec![
            metric_line("Root", percent(number_at(root, "usage_percent")), AMBER),
            text_line("Free", bytes(number_at(root, "free_bytes"))),
            metric_line("Temp", celsius(temp), thermal_color(temp)),
        ]
    } else {
        vec![
            metric_line("Root", percent(number_at(root, "usage_percent")), AMBER),
            text_line("Free", bytes(number_at(root, "free_bytes"))),
            metric_line("Temperature", celsius(temp), thermal_color(temp)),
            text_line(
                "I/O",
                format!(
                    "R {} · W {}",
                    rate(number_at(disk, "total_read_bytes_per_sec")),
                    rate(number_at(disk, "total_write_bytes_per_sec"))
                ),
            ),
            text_line("Health", disk_health(disk)),
        ]
    };
    frame.render_widget(panel(" DISK ", AMBER, lines), area);
}

fn draw_gpu_card(frame: &mut ratatui::Frame, app: &App, area: Rect, compact: bool) {
    let gpu = app.snapshot.get("gpu").unwrap_or(&Value::Null);
    let device = gpu.pointer("/devices/0").unwrap_or(&Value::Null);
    let temp = number(&app.snapshot, "/temperature/hardware/gpu/current_celsius");
    let lines = if compact {
        vec![
            metric_line("Usage", percent(number_at(device, "usage_percent")), PURPLE),
            metric_line(
                "VRAM",
                percent(number_at(device, "vram_usage_percent")),
                PURPLE,
            ),
            metric_line("Temp", celsius(temp), thermal_color(temp)),
        ]
    } else {
        vec![
            metric_line("Usage", percent(number_at(device, "usage_percent")), PURPLE),
            metric_line(
                "VRAM",
                percent(number_at(device, "vram_usage_percent")),
                PURPLE,
            ),
            metric_line("Temperature", celsius(temp), thermal_color(temp)),
            text_line("Core clock", mhz(number_at(device, "core_clock_mhz"))),
            text_line("Driver", string_at(device, "/driver", "Not exposed")),
        ]
    };
    frame.render_widget(panel(" GPU ", PURPLE, lines), area);
}

fn draw_network_and_processes(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let parts = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(57), Constraint::Percentage(43)])
        .split(area);
    let network = app.snapshot.get("network").unwrap_or(&Value::Null);
    let primary = network.get("primary").unwrap_or(&Value::Null);
    let lines = vec![
        Line::from(vec![
            Span::styled("Download ", Style::default().fg(MUTED)),
            Span::styled(
                rate(number_at(network, "download_bytes_per_sec")),
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
            ),
            Span::raw("   "),
            Span::styled("Upload ", Style::default().fg(MUTED)),
            Span::styled(
                rate(number_at(network, "upload_bytes_per_sec")),
                Style::default()
                    .fg(Color::LightBlue)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(Span::styled(
            format!(
                "{} · {} · {}",
                string_at(primary, "/name", "No active link"),
                string_at(primary, "/state", "unknown"),
                string(&app.snapshot, "/network/local_ipv4", "no IP")
            ),
            Style::default().fg(MUTED),
        )),
        Line::from(vec![
            Span::styled("Down ", Style::default().fg(CYAN)),
            Span::raw(sparkline(&app.down_history)),
            Span::raw("  "),
            Span::styled("Up ", Style::default().fg(Color::LightBlue)),
            Span::raw(sparkline(&app.up_history)),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(CYAN))
                .title(" NETWORK "),
        ),
        parts[0],
    );

    let preview = app.processes();
    let mut lines = vec![Line::from(Span::styled(
        "Top CPU now",
        Style::default().fg(MUTED),
    ))];
    let compact_preview = parts[1].width < 45;
    for process in preview.iter().take(if compact_preview { 3 } else { 4 }) {
        let line = if compact_preview {
            format!(
                "{:<12} {:>5}",
                truncate(string_at(process, "/name", "unknown"), 12),
                percent(number_at(process, "cpu_average_percent")),
            )
        } else {
            format!(
                "{:<18} {:>5}  {:>8}",
                truncate(string_at(process, "/name", "unknown"), 18),
                percent(number_at(process, "cpu_average_percent")),
                bytes(number_at(process, "private_bytes")),
            )
        };
        lines.push(Line::from(line));
    }
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(AMBER))
                .title(" PROCESSES "),
        ),
        parts[1],
    );
}

fn draw_processes(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let processes = app.processes();
    let title = match app.process_sort {
        ProcessSort::Cpu => " TOP PROCESSES · CPU ↓ ",
        ProcessSort::Memory => " TOP PROCESSES · MEMORY ↓ ",
    };
    let rows = processes.iter().enumerate().map(|(index, process)| {
        let style = if index == app.selected_process {
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        Row::new(vec![
            Cell::from(string_at(process, "/name", "unknown")),
            Cell::from(
                number_at(process, "pid")
                    .map(|value| value.round().to_string())
                    .unwrap_or_else(|| "—".into()),
            ),
            Cell::from(percent(number_at(process, "cpu_average_percent"))),
            Cell::from(percent(number_at(process, "cpu_percent"))),
            Cell::from(bytes(number_at(process, "private_bytes"))),
        ])
        .style(style)
    });
    let header = Row::new(["Process", "PID", "CPU avg", "CPU now", "RAM"])
        .style(Style::default().fg(CYAN).add_modifier(Modifier::BOLD));
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(46),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .column_spacing(1)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(CYAN))
            .title(title),
    );
    let mut table_state = TableState::default().with_selected(Some(app.selected_process));
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn draw_thermals(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(54), Constraint::Percentage(46)])
        .split(area);
    let sensors = app
        .snapshot
        .pointer("/temperature/sensors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let sensor_rows = sensors.iter().map(|sensor| {
        let value = number_at(sensor, "celsius");
        Row::new(vec![
            Cell::from(string_at(sensor, "/category", "other")),
            Cell::from(string_at(sensor, "/label", "unnamed")),
            Cell::from(celsius(value)),
            Cell::from(string_at(sensor, "/source", "—")),
        ])
        .style(Style::default().fg(thermal_color(value)))
    });
    let thermal_table = Table::new(
        sensor_rows,
        [
            Constraint::Length(13),
            Constraint::Percentage(45),
            Constraint::Length(13),
            Constraint::Percentage(30),
        ],
    )
    .header(
        Row::new(["Category", "Sensor", "Current", "Source"])
            .style(Style::default().fg(RED).add_modifier(Modifier::BOLD)),
    )
    .column_spacing(1)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(RED))
            .title(" HARDWARE THERMALS "),
    );
    frame.render_widget(thermal_table, vertical[0]);

    let memory = app.snapshot.get("memory").unwrap_or(&Value::Null);
    let disk = app.snapshot.get("disk").unwrap_or(&Value::Null);
    let gpu = app.snapshot.get("gpu").unwrap_or(&Value::Null);
    let lines = vec![
        detail_line("CPU", string(&app.snapshot, "/cpu/model", "Not exposed")),
        detail_line("RAM", inventory_memory(memory)),
        detail_line("Disk", string_at(disk, "/inventory/model", "Not exposed")),
        detail_line("Disk health", disk_health(disk)),
        detail_line("GPU", string_at(gpu, "/devices/0/model", "Not detected")),
        detail_line(
            "Kernel",
            string(&app.snapshot, "/uptime/kernel", "Not exposed"),
        ),
    ];
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(PURPLE))
                .title(" HARDWARE INVENTORY "),
        ),
        vertical[1],
    );
}

fn panel<'a>(title: &'a str, color: Color, lines: Vec<Line<'a>>) -> Paragraph<'a> {
    Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(color))
            .title(title),
    )
}

fn metric_line<'a>(label: &'a str, value: String, color: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{label:<12}"), Style::default().fg(MUTED)),
        Span::styled(
            value,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ])
}

fn text_line<'a>(label: &'a str, value: String) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{label:<12}"), Style::default().fg(MUTED)),
        Span::styled(value, Style::default().fg(Color::White)),
    ])
}

fn compact_text_line<'a>(label: &'a str, value: String) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{label:<6}"), Style::default().fg(MUTED)),
        Span::styled(value, Style::default().fg(Color::White)),
    ])
}

fn detail_line(label: &str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<14}"), Style::default().fg(MUTED)),
        Span::styled(value, Style::default().fg(Color::White)),
    ])
}

fn number(value: &Value, pointer: &str) -> Option<f64> {
    value.pointer(pointer).and_then(Value::as_f64)
}

fn number_at(value: &Value, key: &str) -> Option<f64> {
    value.get(key).and_then(Value::as_f64)
}

fn string(value: &Value, pointer: &str, fallback: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .to_owned()
}

fn string_at(value: &Value, pointer: &str, fallback: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .to_owned()
}

fn push_history(history: &mut VecDeque<f64>, value: Option<f64>) {
    history.push_back(value.unwrap_or_default().max(0.0));
    while history.len() > HISTORY_LIMIT {
        history.pop_front();
    }
}

fn percent(value: Option<f64>) -> String {
    value
        .map(|amount| format!("{amount:.1}%"))
        .unwrap_or_else(|| "—".into())
}

fn celsius(value: Option<f64>) -> String {
    value
        .map(|amount| format!("{amount:.1}°C"))
        .unwrap_or_else(|| "—".into())
}

fn watts(value: Option<f64>) -> String {
    value
        .map(|amount| format!("{amount:.1} W"))
        .unwrap_or_else(|| "—".into())
}

fn mhz(value: Option<f64>) -> String {
    value
        .map(|amount| format!("{amount:.0} MHz"))
        .unwrap_or_else(|| "—".into())
}

fn bytes(value: Option<f64>) -> String {
    let Some(mut amount) = value.filter(|value| value.is_finite() && *value >= 0.0) else {
        return "—".into();
    };
    let units = ["B", "kB", "MB", "GB", "TB"];
    let mut index = 0;
    while amount >= 1000.0 && index < units.len() - 1 {
        amount /= 1000.0;
        index += 1;
    }
    let decimals = usize::from(amount < 10.0 && index > 0);
    format!("{amount:.decimals$} {}", units[index])
}

fn rate(value: Option<f64>) -> String {
    let formatted = bytes(value);
    if formatted == "—" {
        formatted
    } else {
        format!("{formatted}/s")
    }
}

fn used_total(value: &Value) -> String {
    format!(
        "{} / {}",
        bytes(number_at(value, "used_bytes")),
        bytes(number_at(value, "total_bytes"))
    )
}

fn compact_used_total(value: &Value) -> String {
    format!(
        "{}/{}",
        bytes(number_at(value, "used_bytes")).replace(' ', ""),
        bytes(number_at(value, "total_bytes")).replace(' ', "")
    )
}

fn duration(value: Option<f64>) -> String {
    let seconds = value.unwrap_or_default().max(0.0) as u64;
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

fn thermal_color(value: Option<f64>) -> Color {
    match value.unwrap_or_default() {
        amount if amount >= 85.0 => RED,
        amount if amount >= 70.0 => AMBER,
        _ => GREEN,
    }
}

fn disk_health(disk: &Value) -> String {
    let health = disk.pointer("/inventory/health").unwrap_or(&Value::Null);
    match number_at(health, "remaining_percent") {
        Some(value) => format!("{value:.0}% remaining"),
        None => string_at(health, "/detail", "Not exposed"),
    }
}

fn inventory_memory(memory: &Value) -> String {
    let inventory = memory.get("inventory").unwrap_or(&Value::Null);
    let model = string_at(inventory, "/model", "Inventory not collected");
    let rate = string_at(inventory, "/nominal_data_rate", "");
    if rate.is_empty() {
        model
    } else {
        format!("{model} · {rate}")
    }
}

fn sparkline(history: &VecDeque<f64>) -> String {
    let glyphs = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max = history.iter().copied().fold(0.0_f64, f64::max);
    if max <= f64::EPSILON {
        return "─".repeat(history.len().max(1));
    }
    history
        .iter()
        .map(|value| glyphs[((value / max) * (glyphs.len() - 1) as f64).round() as usize])
        .collect()
}

fn truncate(value: String, width: usize) -> String {
    let mut chars = value.chars();
    let clipped: String = chars.by_ref().take(width.saturating_sub(1)).collect();
    if chars.next().is_some() {
        format!("{clipped}…")
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn memory_sort_finds_idle_process_beyond_cpu_top_six() {
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        let before: std::collections::HashMap<u32, crate::ProcessCounters> = (0..8)
            .map(|pid| {
                (
                    pid,
                    crate::ProcessCounters {
                        private_bytes: if pid == 7 { 1000 } else { 1 },
                        ..Default::default()
                    },
                )
            })
            .collect();
        let mut after = before.clone();
        for (pid, process) in &mut after {
            process.ticks = u64::from(7 - *pid) * hz;
        }
        let mut state = crate::CollectorState::default();
        let limited = crate::process_snapshot(&before, &after, 1.0, 6, &mut state);
        assert!(
            !limited["top"]
                .as_array()
                .unwrap()
                .iter()
                .any(|process| process["pid"] == 7)
        );
        let processes = crate::process_snapshot(&before, &after, 1.0, usize::MAX, &mut state);
        let mut app = App::new(json!({"processes":processes}), Duration::from_secs(1));
        assert_eq!(app.processes()[0]["pid"], 0);
        app.process_sort = ProcessSort::Memory;
        assert_eq!(app.processes()[0]["pid"], 7);
    }

    #[test]
    fn worker_coalesces_requests_and_joins_on_drop() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let worker_calls = Arc::clone(&calls);
        let worker = SamplingWorker::spawn(move || {
            worker_calls.fetch_add(1, AtomicOrdering::SeqCst);
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(Value::Null)
        });
        worker.request();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        for _ in 0..100 {
            worker.request();
        }
        release_tx.send(()).unwrap();
        drop(worker);
        assert_eq!(calls.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn worker_delivers_failure_and_exits() {
        let mut worker = SamplingWorker::spawn(|| Err("probe failed".into()));
        worker.request();
        worker.join.take().unwrap().join().unwrap();
        assert_eq!(worker.take().unwrap().unwrap_err(), "probe failed");
    }

    #[test]
    fn dropping_worker_bounds_stalled_probe_without_external_release() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let worker = SamplingWorker::spawn(move || {
            entered_tx.send(()).unwrap();
            let output = crate::pci_probe_output(
                std::process::Command::new("sh").args(["-c", "exec sleep 30"]),
                Duration::from_millis(100),
            );
            assert!(output.is_none());
            Ok(Value::Null)
        });
        worker.request();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = Instant::now();
        drop(worker);
        // `drop` must wait for the active worker, but the bounded PCI probe
        // must let it complete promptly without an external unblock signal.
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
