package application

const (
	// This fork publishes its update packages as GitHub release assets:
	// <base>/latest.json and <base>/nanokvm_<version>.tar.gz resolve to the
	// newest stable release. GitHub offers no "latest prerelease" URL, so the
	// preview channel follows the stable one.
	StableURL  = "https://github.com/hhansen06/NanoKVM/releases/latest/download"
	PreviewURL = StableURL

	AppDir    = "/kvmapp"
	BackupDir = "/root/old"
	CacheDir  = "/root/.kvmcache"

	updateWorkspacePrefix = "nanokvm-update-"
	cacheDirMode          = 0o700
	maxPackageSize        = uint64(1 << 30)
	maxExpandedSize       = uint64(2 << 30)
	maxArchiveEntries     = 100_000
	minFreeReserve        = uint64(128 << 20)
	freeReservePercent    = uint64(5)
)

type Service struct{}

func NewService() *Service {
	return &Service{}
}
