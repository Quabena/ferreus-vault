import { useEffect } from "react";
import "../../styles/AboutDrawer.css";

interface AboutDrawerProps {
  isOpen: boolean;
  onClose: () => void;
}

export function AboutDrawer({ isOpen, onClose }: AboutDrawerProps) {
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <>
      <div
        className="about-drawer-backdrop animate-fade-in"
        onClick={onClose}
        aria-hidden="true"
      />

      <aside
        id="about-drawer"
        className="about-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="about-title"
      >
        <header className="about-drawer__header">
          <div>
            <p className="about-drawer__eyebrow">Version 1.0</p>
            <h1 id="about-title" className="about-drawer__title text-display">
              About Ferreus Vault
            </h1>
          </div>
          <button
            type="button"
            className="fv-btn-icon about-drawer__close"
            onClick={onClose}
            aria-label="Close about drawer"
          >
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              aria-hidden="true"
            >
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </header>

        <div className="about-drawer__body">
          <section className="about-section">
            <h2>What is Ferreus Vault?</h2>
            <p>
              Ferreus Vault is a local-first, encrypted password manager built
              for people who take their privacy seriously. It stores your
              credentials exclusively on your own device — no accounts, no
              servers, no subscriptions, no data leaving your machine.
              Everything you save is protected by strong, modern cryptography
              and is only ever accessible to someone who knows your master
              password.
            </p>
            <p>
              Ferreus Vault was built on the belief that a password manager
              should be a vault in the truest sense of the word: sealed,
              private, and entirely yours.
            </p>
          </section>

          <section className="about-section">
            <h2>Core Principles</h2>

            <div className="about-principle">
              <h3>Privacy by design.</h3>
              <p>
                Your passwords never leave your device. There is no cloud sync,
                no telemetry, no analytics, and no third-party service involved
                in the operation of this application. The only copy of your data
                is the one on your filesystem.
              </p>
            </div>

            <div className="about-principle">
              <h3>Security without compromise.</h3>
              <p>
                Ferreus Vault uses Argon2id for key derivation,
                XChaCha20-Poly1305 for authenticated encryption, and HKDF-SHA256
                for device key binding. These algorithms are widely used and
                trusted throughout the cybersecurity industry for protecting
                sensitive information. Sensitive material is zeroized from
                memory the moment it is no longer needed.
              </p>
            </div>

            <div className="about-principle">
              <h3>Minimal attack surface.</h3>
              <p>
                Passwords are never displayed in the interface and never
                transmitted over the internal application channel to the
                frontend. When you copy a password, it travels directly from the
                encrypted vault to your clipboard — it never touches JavaScript,
                developer tools, or IPC logs. The clipboard is automatically
                cleared within 20 seconds.
              </p>
            </div>

            <div className="about-principle">
              <h3>Honest and open.</h3>
              <p>
                Ferreus Vault is licensed under the GNU General Public License
                v3.0. The source code is available for review, audit, and
                contribution. No hidden behaviour, no obfuscation.
              </p>
            </div>
          </section>

          <section className="about-section">
            <h2>Technology</h2>
            <p>
              Ferreus Vault is built with a carefully chosen stack designed for
              performance, safety, and long-term maintainability.
            </p>
            <p>
              The cryptographic core and vault logic are written entirely in{" "}
              <strong>Rust</strong>, a systems programming language whose
              ownership model eliminates entire classes of memory-safety
              vulnerabilities at compile time. The desktop shell is powered by{" "}
              <strong>Tauri v2</strong>, which wraps the Rust backend in a
              lightweight native process and uses the operating system's
              built-in WebView for rendering — resulting in a fast, small, and
              secure application with no bundled browser engine.
            </p>
            <p>
              The user interface is built with <strong>React</strong> and{" "}
              <strong>TypeScript</strong>, providing a responsive and accessible
              experience without the overhead of a heavyweight framework.
            </p>
          </section>

          <section className="about-section">
            <h2>The Developer</h2>
            <p>
              Ferreus Vault is designed and built by <strong>Evans Adu</strong>,
              founder of the Ferreus Vault project, software engineer, and
              advocate for privacy-focused software. His work focuses on
              building secure, reliable, and scalable user experiences.
            </p>
            <dl className="about-contact-list">
              <div>
                <dt>Email</dt>
                <dd>
                  <a href="mailto:evanssaduu@gmail.com">evanssaduu@gmail.com</a>
                </dd>
              </div>
              <div>
                <dt>GitHub</dt>
                <dd>
                  <a
                    href="https://github.com/quabena"
                    target="_blank"
                    rel="noreferrer"
                  >
                    github.com/quabena
                  </a>
                </dd>
              </div>
            </dl>
          </section>

          <section className="about-section">
            <h2>License</h2>
            <p>
              Ferreus Vault is free software. You can redistribute it and/or
              modify it under the terms of the{" "}
              <strong>GNU General Public License version 3</strong>, as
              published by the Free Software Foundation.
            </p>
            <p>
              This program is distributed in the hope that it will be useful,
              but <strong>without any warranty</strong> — without even the
              implied warranty of merchantability or fitness for a particular
              purpose. See the GNU General Public License for full details.
            </p>
            <p>
              A copy of the GPL-3.0 license is included with every distribution
              of Ferreus Vault.
            </p>
          </section>

          <section className="about-section">
            <h2>Contact & Support</h2>
            <dl className="about-contact-list">
              <div>
                <dt>
                  For application issues, bug reports, and general enquiries
                </dt>
                <dd>
                  <a href="mailto:ferreusvault@example.com">
                    ferreusvault@gmail.com
                  </a>
                </dd>
              </div>
              <div>
                <dt>To reach the developer directly</dt>
                <dd>
                  <a href="mailto:evanssaduu@gmail.com">evanssaduu@gmail.com</a>
                </dd>
              </div>
            </dl>
          </section>

          <p className="about-drawer__copyright">Copyright © 2026 Evans Adu.</p>
        </div>
      </aside>
    </>
  );
}
