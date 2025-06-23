import { Button } from "@/components/ui/button";

interface DownloadButtonProps {
  href: string;
  label: string;
}

export const DownloadButton: React.FC<DownloadButtonProps> = ({ href, label }) => (
  <Button asChild>
    <a
      href={href}
      download
      aria-label={label}
    >
      {label}
    </a>
  </Button>
);

export default DownloadButton;
