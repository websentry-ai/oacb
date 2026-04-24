# OACB False-Positive Corpus — Legitimate commands that must NOT block

Every OACB deny rule is tested against this corpus. If a rule blocks any of these commands at baseline tier, the rule is too broad and must be narrowed before merge.

CI gates: this corpus runs on every rule change. Zero false positives at baseline tier.

---

## Node / JavaScript / TypeScript

```
npm install
npm install --save-dev typescript
npm ci
npm run build
npm run test
npm run test -- --watch
npm run lint
npm test -- --coverage
npm update
npm outdated
npm audit
npm audit fix
npx jest
npx tsc --noEmit
pnpm install
pnpm i
pnpm add react react-dom
pnpm dev
pnpm run build
yarn
yarn install
yarn add lodash
yarn dev
bun install
bun test
bun run build
node --version
node -e "console.log(1+1)"
deno task dev
```

## Python

```
pip install -e .
pip install -r requirements.txt
pip install --upgrade pip
pip show django
pip check
pip freeze
uv add requests
uv sync
uv run pytest
uv venv
python -m venv .venv
python -m pytest
python -m pytest tests/
python -m pip install
python -c "import sys; print(sys.version)"
python manage.py test
python manage.py migrate
pytest -v
pytest tests/unit/
ruff check .
ruff format .
mypy .
black .
isort .
```

## Rust

```
cargo build
cargo build --release
cargo test
cargo test -- --nocapture
cargo run
cargo run -- --help
cargo check
cargo clippy
cargo fmt
cargo update
cargo tree
cargo doc --open
cargo install cargo-expand
cargo add serde
rustup update
rustup toolchain install stable
```

## Go

```
go build
go build ./...
go test ./...
go test -v -race ./...
go run main.go
go mod tidy
go mod download
go get -u ./...
go vet ./...
gofmt -w .
golangci-lint run
```

## Ruby

```
bundle install
bundle exec rspec
bundle exec rails server
bundle exec rails console
bundle update
rake test
rake db:migrate
rake db:migrate RAILS_ENV=development
rails new myapp
rails generate model User
```

## Java / Kotlin

```
./gradlew build
./gradlew test
./gradlew bootRun
mvn clean install
mvn test
mvn compile
mvn dependency:tree
```

## Git (non-destructive operations)

```
git status
git diff
git diff HEAD~1
git diff --staged
git diff main..feature-branch
git log
git log --oneline -20
git log --graph --all
git show HEAD
git show abc1234
git branch
git branch -a
git branch -D old-branch
git checkout feature-branch
git checkout -b new-feature
git checkout main
git add .
git add src/
git add -p
git commit -m "feat: add new endpoint"
git commit --amend
git pull
git pull origin main
git pull --rebase
git fetch
git fetch --all
git stash
git stash pop
git stash list
git stash show
git merge feature-branch
git rebase main
git cherry-pick abc1234
git reflog
git blame src/main.py
git bisect start
git tag v1.2.3
```

## GitHub CLI (read-only)

```
gh pr list
gh pr view 123
gh pr diff 123
gh pr checks
gh pr status
gh issue list
gh issue view 456
gh issue comment 456 --body "thanks"
gh release list
gh run list
gh run view 789
gh workflow list
gh auth status
```

## Common Unix

```
ls
ls -la
ls -ltr
cat package.json
cat /etc/os-release
head -20 logfile.txt
tail -f /var/log/nginx/access.log
tail -n 100 /var/log/syslog
grep -r "TODO" src/
grep -n "error" *.log
find . -name "*.py"
find src/ -type f -name "*.ts"
find . -name "node_modules" -type d -prune -o -print
find . -name "*.pyc" -delete    # <-- note: find -delete on relative path is allowed
wc -l src/*.py
sort access.log | uniq -c | sort -rn | head
awk '{print $1}' access.log
sed -i 's/old/new/g' file.txt
pwd
cd ~/projects/app
echo $PATH
echo "Hello, world"
printf "%s\n" foo bar baz
```

## Docker (non-privileged)

```
docker build -t myapp .
docker build -f Dockerfile.dev .
docker run --rm -p 8080:8080 myapp
docker run -it --rm alpine sh
docker run -v $(pwd):/app myapp
docker ps
docker ps -a
docker logs my-container
docker logs -f my-container
docker compose up
docker compose up -d
docker compose down
docker compose logs
docker compose ps
docker compose build
docker exec -it my-container bash
docker exec my-container ls /app
docker inspect my-container
docker image ls
docker image rm myapp:old
docker system df
```

## Kubernetes (read-only + common)

```
kubectl get pods
kubectl get pods -n production
kubectl get services
kubectl get deployments
kubectl get all -n namespace
kubectl describe pod my-pod
kubectl describe deployment my-deploy
kubectl logs my-pod
kubectl logs -f my-pod
kubectl logs my-pod -c container-name
kubectl port-forward svc/my-service 8080:80
kubectl top pods
kubectl config get-contexts
kubectl config current-context
```

## Build tools

```
make
make build
make test
make install
make clean
cmake ..
cmake --build .
bazel build //...
bazel test //...
```

## Package management (non-write)

```
brew info nodejs
brew list
brew outdated
apt list --installed
apt-cache search kubernetes
dpkg -l | grep python
rpm -qa | grep libssl
pacman -Q
```

## Installers (curl|bash) — OACB allowlist of trusted ones

These should pass at baseline (installer allowlist in oacb-enforce.sh):

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
curl -fsSL https://bun.sh/install | bash
curl -LsSf https://astral.sh/uv/install.sh | sh
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -    # sudo path would block at strict+
curl -fsSL https://get.docker.com | sh
```

## Common utilities

```
jq '.name' package.json
jq -r '.dependencies | keys[]' package.json
yq '.services' docker-compose.yml
curl -s https://api.github.com/repos/websentry-ai/oacb | jq .name
curl -fsSL https://registry.npmjs.org/react | jq .description
ripgrep "TODO" src/
rg -t py "def test_" tests/
fd "\.tsx$"
tree -L 2 src/
du -sh node_modules/
df -h .
```

## Read operations on common project files

```
cat README.md
cat package.json
cat pyproject.toml
cat Cargo.toml
cat go.mod
cat Dockerfile
cat docker-compose.yml
cat .github/workflows/ci.yml
cat src/main.py
cat tests/test_app.py
```

## Things that look scary but are not destructive

```
echo "rm -rf /tmp/temp_dir" > cleanup.sh    # writing a script, not running rm
grep -r "delete" src/                         # searching for the word delete
find . -name "*.bak"                          # finding, not deleting
ls -la /                                      # listing root is fine
cat /etc/os-release                           # reading public config
rm tmp.txt                                    # rm without -rf on single file (should be allowed)
rm -f node_modules/.cache/*                   # cleanup cache (allow)
```

## Notes for rule authors

When adding a new deny rule, append one or more examples here of legitimate commands that **almost** match the rule but must not block. Run the conformance runner; it loads this file and checks every entry passes at the target tier.

Rules that cause false positives on any of these entries are reverted or narrowed before merge.
