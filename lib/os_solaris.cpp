/*
 * os_solaris.cpp
 *
 * Home page of code is: https://www.smartmontools.org
 *
 * Copyright (C) 2003-08 SAWADA Keiji
 * Copyright (C) 2003-15 Casper Dik
 * Copyright (C) 2026 OmniOS Community Edition (OmniOSce) Association
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/impl/types.h>
#include <sys/scsi/impl/uscsi.h>
#undef STATUS_CHECK // conflicts with 'enum smart_command_set'

#include "config.h"

#ifdef HAVE_LIBNVME
#include <libdevinfo.h>
#include <libnvme.h>
#endif

#include <smartmon/atacmds.h>
#include <smartmon/scsicmds.h>
#include <smartmon/utility.h>
#include <smartmon/dev_interface.h>
#include <smartmon/nvmecmds.h>

#include <string>
#include <vector>

namespace smartmon {

namespace os_solaris { // No need to publish anything, name provided for Doxygen

static const char * const scsi_drivers[] = {
  "sd",
  "ssd",
  "disk", // SATA devices
  "st",
};

static const char * const ata_drivers[] = {
  "cmdk",
  "dad",
};

static const char ata_unsup_msg[] =
  "Device type 'ata' not implemented, try '-d sat' or '-d sat,12' instead";

// Return true if the device node that 'dev_name' resolves to is named
// after one of the drivers in 'table'.
template <size_t N>
static bool is_dev_type(const char * dev_name, const char * const (& table)[N])
{
  char devpath[MAXPATHLEN];
  if (!realpath(dev_name, devpath))
    return false;

  const char * basename = strrchr(devpath, '/');
  if (!basename)
    return false;
  basename++;

  for (const char * drv : table) {
    size_t l = strlen(drv);
    if (!strncmp(basename, drv, l) && basename[l] == '@')
      return true;
  }
  return false;
}

static bool is_scsi_dev(const char * path)
{
  return is_dev_type(path, scsi_drivers);
}

static bool is_ata_dev(const char * path)
{
  return is_dev_type(path, ata_drivers);
}

/////////////////////////////////////////////////////////////////////////////
/// Shared open/close routines

class solaris_smart_device
: virtual public /*implements*/ smart_device
{
public:
  solaris_smart_device()
    : smart_device(never_called),
      m_fd(-1) { }

  virtual ~solaris_smart_device();

  virtual bool is_open() const override;

  virtual bool open() override;

  virtual bool close() override;

protected:
  /// Return filedesc for derived classes.
  int get_fd() const
    { return m_fd; }

private:
  int m_fd; ///< filedesc, -1 if not open.
};

solaris_smart_device::~solaris_smart_device()
{
  if (m_fd >= 0)
    ::close(m_fd);
}

bool solaris_smart_device::is_open() const
{
  return (m_fd >= 0);
}

bool solaris_smart_device::open()
{
  m_fd = ::open(get_dev_name(), O_RDWR | O_NONBLOCK);
  if (m_fd < 0) {
    set_err((errno == ENOENT || errno == ENOTDIR) ? ENODEV : errno);
    return false;
  }
  return true;
}

bool solaris_smart_device::close()
{
  int fd = m_fd; m_fd = -1;
  if (::close(fd) < 0) {
    set_err(errno);
    return false;
  }
  return true;
}

/////////////////////////////////////////////////////////////////////////////
/// Standard SCSI support via USCSICMD

class solaris_scsi_device
: public /*implements*/ scsi_device,
  public /*extends*/ solaris_smart_device
{
public:
  solaris_scsi_device(smart_interface * intf, const char * dev_name,
    const char * req_type, bool scanning = false);

  virtual smart_device * autodetect_open() override;

  virtual bool scsi_pass_through(scsi_cmnd_io * iop) override;

private:
  bool m_scanning; ///< true if created within scan_smart_devices
};

solaris_scsi_device::solaris_scsi_device(smart_interface * intf,
  const char * dev_name, const char * req_type, bool scanning /* = false */)
: smart_device(intf, dev_name, "scsi", req_type),
  m_scanning(scanning)
{
}

bool solaris_scsi_device::scsi_pass_through(scsi_cmnd_io * iop)
{
  int report = scsi_debugmode;

  if (report > 0) {
    const unsigned char * ucp = iop->cmnd;
    const char * np = scsi_get_opcode_name(ucp);

    lib_printf(" [%s: ", np ? np : "<unknown opcode>");
    for (unsigned k = 0; k < iop->cmnd_len; ++k)
      lib_printf("%02x ", ucp[k]);
    lib_printf("]\n");
    if (report > 1 && iop->dxfer_dir == DXFER_TO_DEVICE && iop->dxferp) {
      int trunc = (iop->dxfer_len > 256) ? 1 : 0;

      lib_printf("  Outgoing data, len=%d%s:\n", (int)iop->dxfer_len,
        (trunc ? " [only first 256 bytes shown]" : ""));
      dStrHex(iop->dxferp, (trunc ? 256 : iop->dxfer_len), 1);
    }
  }

  struct uscsi_cmd uscsi;
  memset(&uscsi, 0, sizeof(uscsi));

  uscsi.uscsi_cdb = reinterpret_cast<char *>(iop->cmnd);
  uscsi.uscsi_cdblen = iop->cmnd_len;
  uscsi.uscsi_timeout = (iop->timeout ? iop->timeout : SCSI_TIMEOUT_DEFAULT);
  uscsi.uscsi_bufaddr = reinterpret_cast<char *>(iop->dxferp);
  uscsi.uscsi_buflen = iop->dxfer_len;
  uscsi.uscsi_rqbuf = reinterpret_cast<char *>(iop->sensep);
  uscsi.uscsi_rqlen = iop->max_sense_len;

  switch (iop->dxfer_dir) {
    case DXFER_NONE:
    case DXFER_FROM_DEVICE:
      uscsi.uscsi_flags = USCSI_READ;
      break;
    case DXFER_TO_DEVICE:
      uscsi.uscsi_flags = USCSI_WRITE;
      break;
    default:
      return set_err(EINVAL);
  }
  uscsi.uscsi_flags |= (USCSI_ISOLATE | USCSI_RQENABLE | USCSI_SILENT);

  if (ioctl(get_fd(), USCSICMD, &uscsi)) {
    int err = errno;
    // errno is set to EIO when a non-zero SCSI completion status is given
    if (!(err == EIO && uscsi.uscsi_status))
      return set_err(err);
  }

  iop->scsi_status = uscsi.uscsi_status;
  iop->resid = uscsi.uscsi_resid;
  iop->resp_sense_len = iop->max_sense_len - uscsi.uscsi_rqresid;

  if (report > 0) {
    int len = iop->resp_sense_len;

    if (iop->scsi_status == SCSI_STATUS_CHECK_CONDITION && iop->sensep && len > 3) {
      if ((iop->sensep[0] & 0x7f) > 0x71)
        lib_printf("  status=%x: [desc] sense_key=%x asc=%x ascq=%x\n",
          iop->scsi_status, iop->sensep[1] & 0xf,
          iop->sensep[2], iop->sensep[3]);
      else
        lib_printf("  status=%x: sense_key=%x asc=%x ascq=%x\n",
          iop->scsi_status, iop->sensep[2] & 0xf,
          iop->sensep[12], iop->sensep[13]);
      if (report > 1) {
        lib_printf("  >>> Sense buffer, len=%d:\n", len);
        dStrHex(iop->sensep, ((len > 252) ? 252 : len), 1);
      }
    }
    else if (iop->scsi_status)
      lib_printf("  status=%x\n", iop->scsi_status);
    if (iop->resid)
      lib_printf("  dxfer_len=%d, resid=%d\n", (int)iop->dxfer_len, iop->resid);
    if (report > 1) {
      len = iop->dxfer_len - iop->resid;
      if (len > 0) {
        int trunc = (len > 256) ? 1 : 0;
        lib_printf("  Incoming data, len=%d%s:\n", len,
          (trunc ? " [only first 256 bytes shown]" : ""));
        dStrHex(iop->dxferp, (trunc ? 256 : len), 1);
      }
    }
  }
  return true;
}

/////////////////////////////////////////////////////////////////////////////
/// SCSI open with autodetection support

smart_device * solaris_scsi_device::autodetect_open()
{
  // Open device
  if (!open())
    return this;

  // No Autodetection if device type was specified by user
  bool sat_only = false;
  if (*get_req_type()) {
    // Detect SAT if device object was created by scan_smart_devices().
    if (!(m_scanning && !strcmp(get_req_type(), "sat")))
      return this;
    sat_only = true;
  }

  // The code below is based on smartd.cpp:SCSIFilterKnown()

  // Get INQUIRY
  unsigned char req_buff[64] = {0, };
  int req_len = 36;
  if (scsiStdInquiry(this, req_buff, req_len)) {
    // Marvell controllers fail on a 36 bytes StdInquiry, but 64 suffices
    // watch this spot ... other devices could lock up here
    req_len = 64;
    if (scsiStdInquiry(this, req_buff, req_len)) {
      // device doesn't like INQUIRY commands
      close();
      set_err(EIO, "INQUIRY failed");
      return this;
    }
  }

  int avail_len = req_buff[4] + 5;
  int len = (avail_len < req_len ? avail_len : req_len);
  if (len < 36) {
    if (sat_only) {
      close();
      set_err(EIO, "INQUIRY too short for SAT");
    }
    return this;
  }

  // Use INQUIRY to detect type

  // SAT or USB ?
  {
    smart_device * newdev = smi()->autodetect_sat_device(this, req_buff, len);
    if (newdev)
      // NOTE: 'this' is now owned by '*newdev'
      return newdev;
  }

  // Nothing special found

  if (sat_only) {
    close();
    set_err(EIO, "Not a SAT device");
  }
  return this;
}

#ifdef HAVE_LIBNVME
/////////////////////////////////////////////////////////////////////////////
/// NVMe support via libnvme

// Return the "nvmeN" controller name if 'dev_name' resolves to a blkdev
// namespace node attached to an nvme controller, empty string otherwise.
// Also return the blkdev unit address in 'bd_addr'.
static std::string nvme_blkdev_ctrl(const char * dev_name, std::string & bd_addr)
{
  char devpath[MAXPATHLEN];
  if (!realpath(dev_name, devpath) || !str_starts_with(devpath, "/devices/"))
    return "";

  std::string path(devpath + sizeof("/devices") - 1);
  size_t slash = path.rfind('/');
  size_t colon = path.rfind(':');
  if (colon != std::string::npos && colon > slash)
    path.erase(colon);

  static const char blkdev[] = "blkdev@";
  if (path.compare(slash + 1, sizeof(blkdev) - 1, blkdev))
    return "";
  bd_addr = path.substr(slash + sizeof(blkdev));
  path.erase(slash);

  di_node_t node = di_init(path.c_str(), DINFOSUBTREE);
  if (node == DI_NODE_NIL)
    return "";
  std::string name;
  const char * drv = di_driver_name(node);
  if (drv && !strcmp(drv, "nvme") && di_instance(node) >= 0)
    name = strprintf("nvme%d", di_instance(node));
  di_fini(node);
  return name;
}

struct nvme_bd_match {
  const char * bd_addr;
  uint32_t nsid;
};

static bool nvme_bd_match_cb(nvme_ctrl_t * ctrl, const nvme_ns_disc_t * disc,
  void * arg)
{
  nvme_bd_match * m = static_cast<nvme_bd_match *>(arg);
  uint32_t nsid = nvme_ns_disc_nsid(disc);
  nvme_ns_info_t * info;
  if (!nvme_ctrl_ns_info_snap(ctrl, nsid, &info))
    return true;

  const char * addr;
  if (nvme_ns_info_bd_addr(info, &addr) && !strcmp(addr, m->bd_addr))
    m->nsid = nsid;
  nvme_ns_info_free(info);
  return !m->nsid;
}

class solaris_nvme_device
: public /*implements*/ nvme_device
{
public:
  solaris_nvme_device(smart_interface * intf, const char * dev_name,
    const char * req_type, unsigned nsid);

  virtual ~solaris_nvme_device();

  virtual bool is_open() const override;

  virtual bool open() override;

  virtual bool close() override;

  virtual bool nvme_pass_through(const nvme_cmd_in & in, nvme_cmd_out & out) override;

private:
  bool set_nvme_lib_err();

  bool get_log_info(uint32_t lid, uint64_t & fixed_size);

  bool read_log_page(uint32_t lid, uint32_t nsid, unsigned lsp, bool rae,
    uint64_t offset, void * buf, size_t size);

  bool set_ctrl_err(nvme_cmd_out & out);

  nvme_t * m_nvme; ///< libnvme handle, nullptr if not open.
  nvme_ctrl_t * m_ctrl; ///< controller handle, nullptr if not open.
};

solaris_nvme_device::solaris_nvme_device(smart_interface * intf,
  const char * dev_name, const char * req_type, unsigned nsid)
: smart_device(intf, dev_name, "nvme", req_type),
  nvme_device(nsid),
  m_nvme(nullptr), m_ctrl(nullptr)
{
}

solaris_nvme_device::~solaris_nvme_device()
{
  if (is_open())
    solaris_nvme_device::close();
}

bool solaris_nvme_device::is_open() const
{
  return !!m_ctrl;
}

bool solaris_nvme_device::set_nvme_lib_err()
{
  int no;
  switch (nvme_err(m_nvme)) {
    case NVME_ERR_PRIVS:
      no = EACCES;
      break;
    case NVME_ERR_BAD_CONTROLLER:
    case NVME_ERR_NS_RANGE:
      no = ENODEV;
      break;
    default:
      no = nvme_syserr(m_nvme);
      if (!no)
        no = EIO;
      break;
  }
  set_err(no, "%s", nvme_errmsg(m_nvme));
  close();
  return false;
}

// Open the controller with nvme_ctrl_ns_init() from either a "nvmeN" or
// "nvmeN/NS" name, or a /dev/rdsk path to a namespace attached to blkdev.
bool solaris_nvme_device::open()
{
  if (!(m_nvme = nvme_init()))
    return set_err(errno ? errno : ENOMEM, "nvme_init() failed");

  const char * dev_name = get_dev_name();
  std::string name, bd_addr;
  if (str_starts_with(dev_name, "nvme"))
    name = dev_name;
  else {
    name = nvme_blkdev_ctrl(dev_name, bd_addr);
    if (name.empty()) {
      close();
      return set_err(ENODEV, "Not an NVMe controller or namespace");
    }
  }

  nvme_ns_t * ns = nullptr;
  if (!nvme_ctrl_ns_init(m_nvme, name.c_str(), &m_ctrl, &ns))
    return set_nvme_lib_err();

  uint32_t nsid = 0;
  if (ns) {
    nvme_ns_info_t * info;
    if (nvme_ns_info_snap(ns, &info)) {
      nsid = nvme_ns_info_nsid(info);
      nvme_ns_info_free(info);
    }
    nvme_ns_fini(ns);
    if (!nsid) {
      set_err(EIO, "%s", nvme_ctrl_errmsg(m_ctrl));
      close();
      return false;
    }
  }
  else if (!bd_addr.empty()) {
    nvme_bd_match m = { bd_addr.c_str(), 0 };
    if (!nvme_ns_discover(m_ctrl, NVME_NS_DISC_F_BLKDEV, nvme_bd_match_cb, &m)
        || !m.nsid) {
      set_err(ENODEV, "Unable to find NVMe namespace for %s", dev_name);
      close();
      return false;
    }
    nsid = m.nsid;
  }
  else
    nsid = nvme_broadcast_nsid;

  if (!get_nsid())
    set_nsid(nsid);
  return true;
}

bool solaris_nvme_device::close()
{
  if (m_ctrl)
    nvme_ctrl_fini(m_ctrl);
  if (m_nvme)
    nvme_fini(m_nvme);
  m_ctrl = nullptr;
  m_nvme = nullptr;
  return true;
}

struct nvme_log_info {
  uint32_t lid;
  bool found;
  uint64_t fixed_size;
};

static bool nvme_log_info_cb(nvme_ctrl_t * /*ctrl*/, const nvme_log_disc_t * disc,
  void * arg)
{
  nvme_log_info * li = static_cast<nvme_log_info *>(arg);
  if (nvme_log_disc_lid(disc) != li->lid || nvme_log_disc_csi(disc) != NVME_CSI_NVM)
    return true;
  li->found = true;
  uint64_t size;
  if (nvme_log_disc_size(disc, &size) == NVME_LOG_SIZE_K_FIXED)
    li->fixed_size = size;
  return false;
}

// Look up log page 'lid' in the set of log pages known to libnvme.
// Return false if it is unknown. Set 'fixed_size' to the size of the
// log page if it is of fixed size, 0 otherwise.
bool solaris_nvme_device::get_log_info(uint32_t lid, uint64_t & fixed_size)
{
  nvme_log_info li = { lid, false, 0 };
  nvme_log_discover(m_ctrl, (nvme_log_disc_scope_t)(NVME_LOG_SCOPE_CTRL |
    NVME_LOG_SCOPE_NVM | NVME_LOG_SCOPE_NS), 0, nvme_log_info_cb, &li);
  fixed_size = li.fixed_size;
  return li.found;
}

bool solaris_nvme_device::read_log_page(uint32_t lid, uint32_t nsid,
  unsigned lsp, bool rae, uint64_t offset, void * buf, size_t size)
{
  nvme_log_req_t * req;
  if (!nvme_log_req_init(m_ctrl, &req))
    return false;
  bool ok = nvme_log_req_set_lid(req, lid)
    && (!nsid || nvme_log_req_set_nsid(req, nsid))
    && (!lsp || nvme_log_req_set_lsp(req, lsp))
    && (!rae || nvme_log_req_set_rae(req, true))
    && (!offset || nvme_log_req_set_offset(req, offset))
    && nvme_log_req_set_output(req, buf, size)
    && nvme_log_req_exec(req);
  nvme_log_req_fini(req);
  return ok;
}

bool solaris_nvme_device::set_ctrl_err(nvme_cmd_out & out)
{
  nvme_err_t err = nvme_ctrl_err(m_ctrl);
  if (err == NVME_ERR_CONTROLLER) {
    uint32_t sct, sc;
    nvme_ctrl_deverr(m_ctrl, &sct, &sc);
    return set_nvme_err(out, ((sct & 0x7) << 8) | (sc & 0xff));
  }

  int no = (err == NVME_ERR_PRIVS ? EACCES : nvme_ctrl_syserr(m_ctrl));
  return set_err(no ? no : EIO, "%s", nvme_ctrl_errmsg(m_ctrl));
}

// The nvme(4D) driver does not provide a generic admin command pass-through,
// so map the commands issued by nvmecmds.cpp onto the libnvme equivalents.
bool solaris_nvme_device::nvme_pass_through(const nvme_cmd_in & in,
  nvme_cmd_out & out)
{
  switch (in.opcode) {
    case nvme_admin_identify: {
      nvme_id_req_t * req;
      if (!nvme_id_req_init_by_cns(m_ctrl, NVME_CSI_NVM, in.cdw10 & 0xff, &req))
        return set_ctrl_err(out);
      bool ok = (!in.nsid || nvme_id_req_set_nsid(req, in.nsid))
        && nvme_id_req_set_output(req, in.buffer, in.size)
        && nvme_id_req_exec(req);
      nvme_id_req_fini(req);
      return (ok ? true : set_ctrl_err(out));
    }

    case nvme_admin_get_log_page: {
      uint32_t lid = in.cdw10 & 0xff;
      unsigned lsp = (in.cdw10 >> 8) & 0x7f;
      bool rae = !!(in.cdw10 & (1U << 15));
      uint64_t offset = in.cdw12 | ((uint64_t)in.cdw13 << 32);

      // nvme(4D) rejects standard log pages it does not know about.
      // It only accepts the full size and no offset for log pages
      // it knows to be of fixed size, such as the Error Information Log
      // whose size depends on the number of entries the controller has.
      // Read the whole page and return the requested part.
      uint64_t full = 0;
      if (!get_log_info(lid, full) && lid < NVME_LOGPAGE_VEND_MIN)
        return set_err(ENOSYS, "NVMe log 0x%02x not supported by nvme(4D)", lid);
      if (!full || (full == in.size && !offset)) {
        if (!read_log_page(lid, in.nsid, lsp, rae, offset, in.buffer, in.size))
          return set_ctrl_err(out);
        return true;
      }
      if (offset > full || in.size > full - offset)
        return set_err(EINVAL, "NVMe log 0x%02x: offset %" PRIu64 " and size %u "
          "exceed log size %" PRIu64, lid, offset, in.size, full);

      std::vector<uint8_t> buf(full);
      if (!read_log_page(lid, in.nsid, lsp, rae, 0, buf.data(), full))
        return set_ctrl_err(out);
      memcpy(in.buffer, buf.data() + offset, in.size);
      return true;
    }

    default:
      return set_err(ENOSYS, "NVMe admin command 0x%02x not supported by nvme(4D)",
        in.opcode);
  }
}

static bool nvme_scan_cb(nvme_t * /*nvme*/, const nvme_ctrl_disc_t * disc,
  void * arg)
{
  auto names = static_cast<std::vector<std::string> *>(arg);
  int inst = di_instance(nvme_ctrl_disc_devi(disc));
  if (inst >= 0)
    names->push_back(strprintf("nvme%d", inst));
  return true;
}
#endif // HAVE_LIBNVME

/////////////////////////////////////////////////////////////////////////////
/// Solaris/illumos platform interface

class solaris_smart_interface
: public /*implements*/ smart_interface
{
public:
  virtual std::string get_os_version_str() override;

  virtual std::string get_app_examples(const char * appname) override;

  virtual bool scan_smart_devices(smart_device_list & devlist, const char * type,
    const char * pattern = 0) override;

protected:
  virtual ata_device * get_ata_device(const char * name, const char * type) override;

  virtual scsi_device * get_scsi_device(const char * name, const char * type) override;

#ifdef HAVE_LIBNVME
  virtual nvme_device * get_nvme_device(const char * name, const char * type,
    unsigned nsid) override;
#endif

  virtual smart_device * autodetect_smart_device(const char * name) override;
};

std::string solaris_smart_interface::get_os_version_str()
{
  struct utsname u;
  if (uname(&u) < 0)
    return smart_interface::get_os_version_str();
  return strprintf("%s %s %s %s", u.sysname, u.release, u.version, u.machine);
}

std::string solaris_smart_interface::get_app_examples(const char * appname)
{
  if (strcmp(appname, "smartctl"))
    return "";
  return
    "=================================================== SMARTCTL EXAMPLES =====\n\n"
    "  smartctl -a /dev/rdsk/c0t0d0s0             (Prints all SMART information)\n\n"
    "  smartctl --smart=on --offlineauto=on --saveauto=on /dev/rdsk/c0t0d0s0\n"
    "                                              (Enables SMART on first disk)\n\n"
    "  smartctl -t long /dev/rdsk/c0t0d0s0 (Executes extended disk self-test)\n\n"
    "  smartctl --attributes --log=selftest --quietmode=errorsonly /dev/rdsk/c0t0d0s0\n"
    "                                      (Prints Self-Test & Attribute errors)\n"
#ifdef HAVE_LIBNVME
    "  smartctl -a nvme0             (Prints all SMART information for NVMe nvme0)\n"
    "  smartctl -a nvme0/1  (Prints all SMART information for namespace 1 of nvme0)\n"
#endif
    ;
}

ata_device * solaris_smart_interface::get_ata_device(const char * /*name*/,
  const char * /*type*/)
{
  return set_err_np(ENOSYS, ata_unsup_msg);
}

scsi_device * solaris_smart_interface::get_scsi_device(const char * name,
  const char * type)
{
  return new solaris_scsi_device(this, name, type);
}

#ifdef HAVE_LIBNVME
nvme_device * solaris_smart_interface::get_nvme_device(const char * name,
  const char * type, unsigned nsid)
{
  return new solaris_nvme_device(this, name, type, nsid);
}
#endif

smart_device * solaris_smart_interface::autodetect_smart_device(const char * name)
{
  if (is_scsi_dev(name))
    return get_scsi_device(name, "");
#ifdef HAVE_LIBNVME
  std::string bd_addr;
  if (str_starts_with(name, "nvme") || !nvme_blkdev_ctrl(name, bd_addr).empty())
    return get_nvme_device(name, "", 0);
#endif
  if (is_ata_dev(name))
    return set_err_np(ENOSYS, ata_unsup_msg);
  return nullptr;
}

// Add the paths matching 'dir_pattern' that pass 'testfun' and, if given,
// also match the user supplied shell 'pattern' to 'names'.
static void glob_dev_names(const char * dir_pattern, bool (* testfun)(const char *),
  const char * pattern, std::vector<std::string> & names)
{
  glob_t g;
  if (!glob(dir_pattern, 0, nullptr, &g)) {
    for (size_t i = 0; i < g.gl_pathc; i++) {
      const char * n = g.gl_pathv[i];
      if ((!pattern || !fnmatch(pattern, n, 0)) && testfun(n))
        names.push_back(n);
    }
  }
  globfree(&g);
}

// Tape drives are represented by the all-digit device.
static bool is_scsi_tape(const char * path)
{
  const char * n = strrchr(path, '/') + 1;
  return (!n[strspn(n, "0123456789")] && is_scsi_dev(path));
}

bool solaris_smart_interface::scan_smart_devices(smart_device_list & devlist,
  const char * type, const char * pattern /*= 0*/)
{
  if (!type)
    type = "";

  bool scan_scsi = !*type || !strcmp(type, "scsi") || !strcmp(type, "sat");

  if (scan_scsi) {
    std::vector<std::string> names;
    // Disks are represented by slice 0
    glob_dev_names("/dev/rdsk/*s0", is_scsi_dev, pattern, names);
    glob_dev_names("/dev/rmt/[0-9]*", is_scsi_tape, pattern, names);
    for (const auto & n : names)
      devlist.push_back(new solaris_scsi_device(this, n.c_str(), type,
        true /*scanning*/));
  }

#ifdef HAVE_LIBNVME
  bool scan_nvme = !*type || !strcmp(type, "nvme");

  if (scan_nvme) {
    nvme_t * nvme = nvme_init();
    if (nvme) {
      std::vector<std::string> names;
      nvme_ctrl_discover(nvme, nvme_scan_cb, &names);
      nvme_fini(nvme);
      for (const auto & n : names) {
        if (!pattern || !fnmatch(pattern, n.c_str(), 0))
          devlist.push_back(get_nvme_device(n.c_str(), type, 0));
      }
    }
  }
#endif

  return true;
}

} // namespace os_solaris

/////////////////////////////////////////////////////////////////////////////
/// Initialize platform interface and register with smi()

void smart_interface::init()
{
  static os_solaris::solaris_smart_interface the_interface;
  smart_interface::set(&the_interface);
}

} // namespace smartmon
