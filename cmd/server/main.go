package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/ibm-hyper-protect/contract-manager/internal/config"
	"github.com/ibm-hyper-protect/contract-manager/internal/contract/contractgo"
	"github.com/ibm-hyper-protect/contract-manager/internal/handler"
	keydb "github.com/ibm-hyper-protect/contract-manager/internal/keymgmt/db"
	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	setupLogger(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to create database pool", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}

	queries := repository.New(pool)

	if err := seedAdmin(ctx, pool, cfg.BcryptCost); err != nil {
		slog.Error("failed to seed admin user", "error", err)
		os.Exit(1)
	}

	// Services
	engine := contractgo.New()
	keyProvider := keydb.New(queries)

	auditService := service.NewAuditService(queries)
	systemLogService := service.NewSystemLogService(queries)
	roleService := service.NewRoleService(queries)
	rotationService := service.NewRotationService(queries)
	verificationService := service.NewVerificationService(queries)
	userService := service.NewUserService(queries, cfg.BcryptCost)
	userKeyService := service.NewUserKeyService(pool, queries)
	authService := service.NewAuthService(queries, cfg.BcryptCost, cfg.TokenExpiry)
	buildService := service.NewBuildService(queries, auditService)
	assignmentService := service.NewAssignmentService(queries, auditService)
	exportService := service.NewExportService(queries, auditService, assignmentService)
	keyService := service.NewKeyService(queries, pool, buildService, assignmentService, auditService, keyProvider, engine)
	contractService := service.NewContractService(queries, pool, buildService, assignmentService, keyService, keyProvider, engine)
	attestationService := service.NewAttestationService(queries, pool, assignmentService, auditService, keyProvider, engine)

	middleware.SetSystemLogHook(systemLogService.LogEvent)
	middleware.SetTrustProxyHeaders(cfg.TrustProxyHeaders)

	// Handlers
	authHandler := handler.NewAuthHandler(authService, systemLogService)
	userKeyHandler := handler.NewUserKeyHandler(userKeyService, systemLogService)
	userHandler := handler.NewUserHandler(userService, userKeyService, systemLogService)
	roleHandler := handler.NewRoleHandler(roleService)
	buildHandler := handler.NewBuildHandler(buildService, systemLogService)
	assignmentHandler := handler.NewAssignmentHandler(assignmentService, systemLogService)
	keyHandler := handler.NewKeyHandler(keyService, systemLogService)
	contractHandler := handler.NewContractHandler(contractService, systemLogService)
	exportHandler := handler.NewExportHandler(exportService, verificationService, systemLogService)
	attestationHandler := handler.NewAttestationHandler(attestationService, systemLogService)
	auditHandler := handler.NewAuditHandler(auditService)
	rotationHandler := handler.NewRotationHandler(rotationService, systemLogService)
	systemLogHandler := handler.NewSystemLogHandler(systemLogService)
	aboutHandler := handler.NewAboutHandler()
	swaggerHandler := handler.NewSwaggerHandler()

	admin := model.RoleAdmin.String()
	auditor := model.RoleAuditor.String()

	r := chi.NewRouter()
	r.Use(middleware.Recoverer())
	r.Use(middleware.RequestID())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.Logging())
	r.Use(middleware.CORS(cfg.CORSAllowedOrigins, cfg.CORSAllowAll))
	r.Use(middleware.MaxBodyBytes(cfg.MaxPayloadSize))
	r.Use(middleware.RequestTimeout(cfg.RequestTimeout))
	r.Use(middleware.RateLimit())

	// Public
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := pool.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"unhealthy"}`))
			return
		}
		w.Write([]byte(`{"status":"ok"}`))
	})
	r.Get("/about", aboutHandler.GetAbout)
	r.Get("/openapi.json", swaggerHandler.OpenAPISpec)
	r.Get("/swagger", swaggerHandler.UI)
	r.Get("/swagger/", swaggerHandler.UI)
	r.With(middleware.AuthRateLimit()).Post("/auth/login", authHandler.Login)

	// Authenticated
	r.Group(func(r chi.Router) {
		r.Use(middleware.Auth(queries, cfg.TokenExpiry))
		r.Use(middleware.SetupGuard())
		r.Use(middleware.RequireRequestSignature(userKeyService))

		r.Post("/auth/logout", authHandler.Logout)
		r.Get("/roles", roleHandler.ListRoles)

		r.Route("/users", func(r chi.Router) {
			r.With(middleware.RequireRole(admin, auditor)).Get("/", userHandler.ListUsers)
			r.With(middleware.RequireRole(admin)).Post("/", userHandler.CreateUser)

			r.Route("/{id}", func(r chi.Router) {
				r.Group(func(r chi.Router) {
					r.Use(middleware.RequireRole(admin))
					r.Patch("/", userHandler.UpdateUserProfile)
					r.Delete("/", userHandler.DeactivateUser)
					r.Patch("/roles", userHandler.UpdateRoles)
					r.Patch("/reactivate", userHandler.ReactivateUser)
					r.Patch("/reset-password", userHandler.AdminResetPassword)
					r.Post("/public-keys/revoke-all", userKeyHandler.RevokeAllKeys)
				})
				r.Group(func(r chi.Router) {
					r.Use(middleware.RequireOwnerOrAdmin("id"))
					r.Get("/public-keys", userKeyHandler.ListKeys)
					r.Delete("/public-keys/{key_id}", userKeyHandler.RevokeKey)
					r.With(middleware.StrictRateLimit()).Put("/public-key", userHandler.RegisterPublicKey)
					r.Get("/public-key", userHandler.GetPublicKey)
					r.Patch("/password", userHandler.ChangePassword)
					r.Get("/tokens", userHandler.ListTokens)
					r.With(middleware.StrictRateLimit()).Post("/tokens", userHandler.CreateToken)
					r.Delete("/tokens/{token_id}", userHandler.RevokeToken)
					r.Get("/assignments", assignmentHandler.GetUserAssignments)
				})
			})
		})

		r.With(middleware.RequireRole(admin, auditor)).Get("/system-logs", systemLogHandler.ListSystemLogs)

		// Contract helpers (registered with and without the /v2 prefix used by the desktop app)
		for _, prefix := range []string{"", "/v2"} {
			r.Post(prefix+"/contract-template", contractHandler.GetContractTemplate)
			r.Get(prefix+"/encryption-certificates/versions", contractHandler.ListAvailableEncCertVersions)
		}

		r.Route("/builds", func(r chi.Router) {
			r.Get("/", buildHandler.ListBuilds)
			r.With(middleware.RequireRole(admin, auditor)).Post("/", buildHandler.CreateBuild)

			r.Route("/{id}", func(r chi.Router) {
				r.Use(middleware.RequireBuildAccess(queries, "id"))

				r.Get("/", buildHandler.GetBuild)
				r.With(middleware.RequireRole(admin, auditor)).Post("/cancel", buildHandler.CancelBuild)

				r.Get("/audit", auditHandler.GetAuditTrail)
				r.Get("/audit-trail", auditHandler.GetAuditTrail)

				r.Get("/assignments", assignmentHandler.GetBuildAssignments)
				r.With(middleware.RequireRole(admin, auditor)).Post("/assignments", assignmentHandler.CreateAssignment)
				r.With(middleware.RequireRole(admin)).Delete("/assignments", assignmentHandler.DeleteBuildAssignments)

				r.Get("/export", exportHandler.ExportContract)
				r.Get("/userdata", exportHandler.GetUserData)
				r.Post("/acknowledge-download", exportHandler.AcknowledgeDownload)
				r.Get("/verify", exportHandler.VerifyAuditChain)
				r.Get("/verify-contract", exportHandler.VerifyContractIntegrity)

				r.With(middleware.RequireRole(auditor)).Post("/keys/signing", keyHandler.RegisterSigningKey)
				r.With(middleware.RequireRole(auditor)).Post("/keys/attestation", keyHandler.RegisterAttestationKey)
				r.Get("/keys/signing/public", keyHandler.GetSigningPublicKey)

				for _, prefix := range []string{"", "/v2"} {
					r.Post(prefix+"/sections/workload", contractHandler.SubmitWorkload)
					r.Post(prefix+"/sections/environment", contractHandler.SubmitEnvironment)
					r.With(middleware.RequireRole(auditor)).Post(prefix+"/finalize", contractHandler.FinalizeContract)
				}

				r.Post("/attestation/evidence", attestationHandler.UploadEvidence)
				r.Post("/attestation/evidence/{evidence_id}/verify", attestationHandler.VerifyEvidence)
				r.Get("/attestation/status", attestationHandler.GetVerificationStatus)
			})
		})

		r.Route("/rotation", func(r chi.Router) {
			r.Use(middleware.RequireRole(admin))
			r.Get("/expired", rotationHandler.GetExpiredCredentials)
			r.Post("/force-password-change/{user_id}", rotationHandler.ForcePasswordChange)
			r.Post("/revoke-key/{user_id}", rotationHandler.RevokeExpiredPublicKey)
		})
	})

	go rotationService.StartRotationMonitor(ctx, 24*time.Hour)

	srv := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		slog.Info("server starting", "addr", cfg.Addr())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server failed", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down server")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
	}
}

func setupLogger(cfg *config.Config) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if strings.EqualFold(cfg.LogFormat, "text") {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(h))
}

// seedAdmin creates the initial ADMIN user from ADMIN_EMAIL / ADMIN_PASSWORD / ADMIN_NAME
// if no user with that email exists yet.
func seedAdmin(ctx context.Context, pool *pgxpool.Pool, bcryptCost int) error {
	email := strings.TrimSpace(os.Getenv("ADMIN_EMAIL"))
	password := os.Getenv("ADMIN_PASSWORD")
	name := strings.TrimSpace(os.Getenv("ADMIN_NAME"))
	if email == "" || password == "" {
		slog.Info("ADMIN_EMAIL/ADMIN_PASSWORD not set, skipping admin seeding")
		return nil
	}
	if name == "" {
		name = "System Admin"
	}

	// Keep the user and initial role together if either write fails.
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin admin seeding: %w", err)
	}
	defer tx.Rollback(ctx)
	queries := repository.New(tx)
	if _, err := queries.GetUserByEmail(ctx, email); err == nil {
		slog.Info("admin user already exists, skipping seeding", "email", email)
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("look up initial admin: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return fmt.Errorf("hash initial admin password: %w", err)
	}
	user, err := queries.CreateUser(ctx, repository.CreateUserParams{
		Name:         name,
		Email:        email,
		PasswordHash: string(hash),
	})
	if err != nil {
		return fmt.Errorf("create initial admin: %w", err)
	}
	if _, err := queries.AssignRole(ctx, repository.AssignRoleParams{
		UserID:     user.ID,
		Role:       model.RoleAdmin.String(),
		AssignedBy: user.ID,
	}); err != nil {
		return fmt.Errorf("assign initial admin role: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit admin seeding: %w", err)
	}
	slog.Info("seeded admin user", "email", email)
	return nil
}
