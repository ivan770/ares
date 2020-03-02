use indicatif::{ProgressBar, ProgressStyle};

pub struct Progress {
    progress: ProgressBar,
}

impl Progress {
    pub fn make() -> Self {
        Progress {
            progress: ProgressBar::new_spinner(),
        }
    }

    pub fn spawn_thread(&self) -> &Self {
        self.progress.enable_steady_tick(120);

        self
    }

    pub fn apply_styles(&self) -> &Self {
        self.progress.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", ""])
                .template("{spinner:.blue} {msg}"),
        );

        self
    }

    pub fn start(&self, msg: &str) -> &Self {
        self.progress.set_message(msg);

        self
    }

    pub fn end(&self) {
        self.progress.finish_and_clear();
    }
}
